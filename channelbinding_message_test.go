// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// challengeWithTargetInfo builds CHALLENGE message bytes (MS-NLMP 2.2.1.2) that
// carry the given AV_PAIR list and no target name, which is the shape IIS sends.
func challengeWithTargetInfo(t *testing.T, targetInfo []byte) []byte {
	t.Helper()

	const (
		signature = "NTLMSSP\x00"
		headerLen = 8 + 4 + 8 + 4 + 8 + 8 + 8
	)

	flags := negotiateFlagNTLMSSPNEGOTIATEUNICODE | negotiateFlagNTLMSSPNEGOTIATETARGETINFO |
		negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY | negotiateFlagNTLMSSPNEGOTIATENTLM

	buf := bytes.NewBuffer(make([]byte, 0, headerLen+len(targetInfo)))
	buf.WriteString(signature)
	buf.Write(binary.LittleEndian.AppendUint32(nil, 2)) // MessageType: CHALLENGE

	// TargetName: absent.
	buf.Write(binary.LittleEndian.AppendUint16(nil, 0))
	buf.Write(binary.LittleEndian.AppendUint16(nil, 0))
	buf.Write(binary.LittleEndian.AppendUint32(nil, headerLen))

	buf.Write(binary.LittleEndian.AppendUint32(nil, uint32(flags)))
	buf.Write(bytes.Repeat([]byte{0x11}, 8)) // ServerChallenge
	buf.Write(make([]byte, 8))               // Reserved

	// TargetInfo follows the fixed header.
	buf.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(targetInfo))))
	buf.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(targetInfo))))
	buf.Write(binary.LittleEndian.AppendUint32(nil, headerLen))
	buf.Write(targetInfo)

	return buf.Bytes()
}

// TestAuthenticateMessageCarriesChannelBinding checks that the AUTHENTICATE
// message sends the MsvAvChannelBindings and MsvAvTargetName pairs IIS Extended
// Protection requires, and that they are absent when the caller does not ask for
// them.
func TestAuthenticateMessageCarriesChannelBinding(t *testing.T) {
	t.Parallel()

	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, 133000000000000000)

	targetInfo := appendAVPair(nil, avIDMsvAvNbDomainName, toUnicode("EXAMPLE"))
	targetInfo = appendAVPair(targetInfo, avIDMsvAvTimestamp, timestamp)
	targetInfo = append(targetInfo, 0, 0, 0, 0) // MsvAvEOL

	binding := []byte("tls-server-end-point:0123456789abcdef0123456789abcdef")
	const spn = "HTTP/ca.example.com"

	t.Run("binding and target name are present", func(t *testing.T) {
		t.Parallel()

		message, err := NewAuthenticateMessage(
			challengeWithTargetInfo(t, targetInfo),
			`EXAMPLE\svc-adcs`,
			"changeme",
			&AuthenticateMessageOptions{ChannelBinding: binding, TargetName: spn},
		)
		if err != nil {
			t.Fatalf("NewAuthenticateMessage() error = %v", err)
		}

		wantBinding := appendAVPair(nil, avIDMsvChannelBindings, computeChannelBindingHash(binding))
		if !bytes.Contains(message, wantBinding) {
			t.Errorf("AUTHENTICATE message does not carry MsvAvChannelBindings %s",
				hex.EncodeToString(wantBinding))
		}

		wantTargetName := appendAVPair(nil, avIDMsvAvTargetName, toUnicode(spn))
		if !bytes.Contains(message, wantTargetName) {
			t.Errorf("AUTHENTICATE message does not carry MsvAvTargetName %s",
				hex.EncodeToString(wantTargetName))
		}
	})

	t.Run("absent when not requested", func(t *testing.T) {
		t.Parallel()

		message, err := NewAuthenticateMessage(
			challengeWithTargetInfo(t, targetInfo),
			`EXAMPLE\svc-adcs`,
			"changeme",
			&AuthenticateMessageOptions{},
		)
		if err != nil {
			t.Fatalf("NewAuthenticateMessage() error = %v", err)
		}

		idBytes := binary.LittleEndian.AppendUint16(nil, uint16(avIDMsvChannelBindings))
		if bytes.Contains(message, idBytes) {
			t.Error("AUTHENTICATE message carries MsvAvChannelBindings although none was requested")
		}
	})
}

// TestWithAVPairs checks the AV_PAIR list rewriting the channel binding relies on.
func TestWithAVPairs(t *testing.T) {
	t.Parallel()

	existing := appendAVPair(nil, avIDMsvAvNbDomainName, toUnicode("EXAMPLE"))
	existing = appendAVPair(existing, avIDMsvAvTargetName, toUnicode("HTTP/old.example.com"))
	existing = append(existing, 0, 0, 0, 0)

	got, err := withAVPairs(existing, avPair{id: avIDMsvAvTargetName, value: toUnicode("HTTP/new.example.com")})
	if err != nil {
		t.Fatalf("withAVPairs() error = %v", err)
	}

	if bytes.Contains(got, toUnicode("HTTP/old.example.com")) {
		t.Error("the existing MsvAvTargetName value was not replaced")
	}

	if !bytes.Contains(got, toUnicode("HTTP/new.example.com")) {
		t.Error("the new MsvAvTargetName value is missing")
	}

	// The unrelated pair survives, and the list stays terminated.
	if !bytes.Contains(got, toUnicode("EXAMPLE")) {
		t.Error("the untouched MsvAvNbDomainName pair was lost")
	}

	if !bytes.HasSuffix(got, []byte{0, 0, 0, 0}) {
		t.Error("the list is not terminated with MsvAvEOL")
	}

	t.Run("malformed input is rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := withAVPairs([]byte{1, 0, 16, 0}, avPair{id: avIDMsvAvFlags}); err == nil {
			t.Error("withAVPairs() error = nil, want an error for a truncated AV_PAIR")
		}
	})
}
