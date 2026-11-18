// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"crypto"
	"crypto/md5" //nolint:gosec // mandated by MS-NLMP for the channel binding hash.
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// channelBindingPrefix is the GSS-API channel binding type for a TLS server
// certificate endpoint, per RFC 5929 section 4.1.
const channelBindingPrefix = "tls-server-end-point:"

// channelBindingSize is the size of the MD5 hash that MS-NLMP 2.2.2.1 places in
// the MsvAvChannelBindings AV_PAIR.
const channelBindingSize = 16

// makeChannelBinding returns the GSS channel binding for the server certificate
// of a TLS connection, which is the form MS-NLMP 2.2.2.1 refers to as
// "tls-server-end-point".
//
// IIS requires the value when the enrollment site enables Extended Protection
// with "Extended Protection: Required": a client that omits it is rejected with
// 401 even when the credentials are correct, which is indistinguishable from a
// wrong password.
func makeChannelBinding(state tls.ConnectionState) ([]byte, error) {
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return nil, errors.New("ntlmssp: TLS connection has no peer certificate to bind")
	}

	certificate := state.PeerCertificates[0]

	hash, err := channelBindingHash(certificate)
	if err != nil {
		return nil, err
	}

	hasher := hash.New()
	if _, err := hasher.Write(certificate.Raw); err != nil {
		return nil, fmt.Errorf("ntlmssp: hash server certificate: %w", err)
	}

	binding := make([]byte, 0, len(channelBindingPrefix)+hasher.Size())
	binding = append(binding, channelBindingPrefix...)

	return hasher.Sum(binding), nil
}

// channelBindingHash returns the hash function RFC 5929 section 4.1 requires for
// a certificate: the one used by its signature algorithm, with MD5 and SHA-1
// upgraded to SHA-256 because it is the certificate that is hashed, not the
// signature, and those two are too weak to be worth honouring.
func channelBindingHash(certificate *x509.Certificate) (crypto.Hash, error) {
	switch certificate.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384, nil
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512, nil
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA256, nil
	default:
		// The remaining algorithms are the SHA-256 family, which RFC 5929 makes
		// the default, and anything newer, for which SHA-256 is still the
		// interoperable choice.
		return crypto.SHA256, nil
	}
}

// computeChannelBindingHash returns the MsvAvChannelBindings value for a channel
// binding: the MD5 of a gss_channel_bindings_struct carrying it, per MS-NLMP
// 3.1.5.1.2 and RFC 2744 section 3.11.
//
// A nil binding yields sixteen zero bytes, which MS-NLMP defines as the
// "no channel bindings" value.
func computeChannelBindingHash(channelBinding []byte) []byte {
	if len(channelBinding) == 0 {
		return make([]byte, channelBindingSize)
	}

	// gss_channel_bindings_struct with null initiator and acceptor addresses:
	// four 32-bit zero words (two address types and two empty lengths), then the
	// application data length and the application data itself.
	buf := make([]byte, 0, 16+4+len(channelBinding))
	buf = append(buf, make([]byte, 16)...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(channelBinding)))
	buf = append(buf, channelBinding...)

	sum := md5Sum(buf)

	return sum[:channelBindingSize]
}

// md5Sum returns the MD5 of data. It is used only where the protocol mandates
// MD5 (the channel binding hash and HMAC-MD5 in MS-NLMP), never as a security
// primitive of its own.
func md5Sum(data []byte) [16]byte {
	//nolint:gosec // MD5 is mandated by MS-NLMP 3.1.5.1.2 for this field.
	return md5.Sum(data)
}

// spnForHost returns the service principal name of the enrollment endpoint,
// which MS-NLMP 3.1.5.1.2 expects in MsvAvTargetName.
//
// IIS registers "HTTP/<host>", so the port is dropped: including it makes the
// name fail to match on any deployment that is not on the default port.
func spnForHost(host string) string {
	if host == "" {
		return ""
	}

	name := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		name = hostOnly
	}

	return "HTTP/" + strings.ToLower(name)
}
