// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"encoding/binary"
	"errors"
)

type avID uint16

const (
	avIDMsvAvEOL avID = iota
	avIDMsvAvNbComputerName
	avIDMsvAvNbDomainName
	avIDMsvAvDNSComputerName
	avIDMsvAvDNSDomainName
	avIDMsvAvDNSTreeName
	avIDMsvAvFlags
	avIDMsvAvTimestamp
	avIDMsvAvSingleHost
	avIDMsvAvTargetName
	avIDMsvChannelBindings
)

// avFlagMICProvided is the MsvAvFlags bit indicating that the client is
// providing a MIC in the AUTHENTICATE message (MS-NLMP 2.2.2.1).
const avFlagMICProvided = 0x00000002

// withMICFlag returns a copy of the targetInfo AV_PAIR list with the
// MIC-provided bit set in MsvAvFlags, adding that pair before MsvAvEOL if it
// is absent (MS-NLMP 3.1.5.1.2).
func withMICFlag(targetInfo []byte) ([]byte, error) {
	out := make([]byte, 0, len(targetInfo)+8)
	found := false
	for len(targetInfo) >= 4 {
		id := avID(binary.LittleEndian.Uint16(targetInfo))
		l := int(binary.LittleEndian.Uint16(targetInfo[2:]))
		if id == avIDMsvAvEOL {
			break
		}
		if len(targetInfo) < 4+l {
			return nil, errors.New("AV_PAIR extends beyond target info")
		}
		start := len(out)
		out = append(out, targetInfo[:4+l]...)
		targetInfo = targetInfo[4+l:]
		if id == avIDMsvAvFlags && l == 4 {
			v := out[start+4:]
			binary.LittleEndian.PutUint32(v, binary.LittleEndian.Uint32(v)|avFlagMICProvided)
			found = true
		}
	}
	if !found {
		out = binary.LittleEndian.AppendUint16(out, uint16(avIDMsvAvFlags))
		out = binary.LittleEndian.AppendUint16(out, 4)
		out = binary.LittleEndian.AppendUint32(out, avFlagMICProvided)
	}
	return append(out, 0, 0, 0, 0), nil // MsvAvEOL
}

// avPair is one AV_PAIR of a target info list.
type avPair struct {
	id    avID
	value []byte
}

// withAVPairs returns a copy of the targetInfo AV_PAIR list with pairs set,
// replacing the value of a pair that is already present, appending the ones that
// are not, and terminating the list with MsvAvEOL.
//
// It is the same walk as [withMICFlag], generalised, because the channel binding
// and the target name both have to be added to the server's list before the
// NTLMv2 response is computed over it (MS-NLMP 3.1.5.1.2).
func withAVPairs(targetInfo []byte, pairs ...avPair) ([]byte, error) {
	out := make([]byte, 0, len(targetInfo)+64)
	written := make([]bool, len(pairs))

	for len(targetInfo) >= 4 {
		id := avID(binary.LittleEndian.Uint16(targetInfo))
		if id == avIDMsvAvEOL {
			break
		}

		l := int(binary.LittleEndian.Uint16(targetInfo[2:]))
		if len(targetInfo) < 4+l {
			return nil, errors.New("AV_PAIR extends beyond target info")
		}

		replaced := false
		for i, pair := range pairs {
			if pair.id != id {
				continue
			}

			out = appendAVPair(out, pair.id, pair.value)
			written[i] = true
			replaced = true

			break
		}

		if !replaced {
			out = append(out, targetInfo[:4+l]...)
		}

		targetInfo = targetInfo[4+l:]
	}

	for i, pair := range pairs {
		if !written[i] {
			out = appendAVPair(out, pair.id, pair.value)
		}
	}

	return append(out, 0, 0, 0, 0), nil // MsvAvEOL
}

// appendAVPair appends one AV_PAIR to out.
func appendAVPair(out []byte, id avID, value []byte) []byte {
	out = binary.LittleEndian.AppendUint16(out, uint16(id))
	out = binary.LittleEndian.AppendUint16(out, uint16(len(value)))

	return append(out, value...)
}

// avPairs returns the AV_PAIRs the options ask for, in the order they are added
// to the server's target info.
func (o *AuthenticateMessageOptions) avPairs() []avPair {
	var pairs []avPair

	if len(o.ChannelBinding) > 0 {
		pairs = append(pairs, avPair{id: avIDMsvChannelBindings, value: computeChannelBindingHash(o.ChannelBinding)})
	}

	if o.TargetName != "" {
		pairs = append(pairs, avPair{id: avIDMsvAvTargetName, value: toUnicode(o.TargetName)})
	}

	return pairs
}
