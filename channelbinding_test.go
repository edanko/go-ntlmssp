// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // the protocol mandates MD5 here.
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// testCertificate returns a certificate with the given signature algorithm and a
// private key usable for it, self-signed for the test.
func testCertificate(t *testing.T, algorithm x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "ca.example.com"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		DNSNames:           []string{"ca.example.com"},
		SignatureAlgorithm: algorithm,
	}

	var (
		der []byte
		err error
	)

	switch algorithm {
	case x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.SHA256WithRSAPSS:
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			t.Fatalf("generate RSA key: %v", keyErr)
		}

		der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	case x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.ECDSAWithSHA256, x509.ECDSAWithSHA1:
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatalf("generate ECDSA key: %v", keyErr)
		}

		der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	case x509.PureEd25519:
		public, private, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatalf("generate Ed25519 key: %v", keyErr)
		}

		der, err = x509.CreateCertificate(rand.Reader, template, template, public, private)
	default:
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			t.Fatalf("generate RSA key: %v", keyErr)
		}

		der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	}

	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return certificate
}

func TestMakeChannelBinding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		algorithm x509.SignatureAlgorithm
		wantHash  int // digest length the binding must carry
	}{
		"rsa sha256": {algorithm: x509.SHA256WithRSA, wantHash: 32},
		"rsa sha384": {algorithm: x509.SHA384WithRSA, wantHash: 48},
		"rsa sha512": {algorithm: x509.SHA512WithRSA, wantHash: 64},
		"rsa pss":    {algorithm: x509.SHA512WithRSAPSS, wantHash: 64},
		"ecdsa 384":  {algorithm: x509.ECDSAWithSHA384, wantHash: 48},
		"ecdsa 512":  {algorithm: x509.ECDSAWithSHA512, wantHash: 64},
		// RFC 5929 section 4.1 upgrades MD5 and SHA-1 to SHA-256.
		"sha1 upgraded to sha256": {algorithm: x509.SHA1WithRSA, wantHash: 32},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			certificate := testCertificate(t, test.algorithm)
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}

			binding, err := makeChannelBinding(state)
			if err != nil {
				t.Fatalf("makeChannelBinding() error = %v", err)
			}

			if !bytes.HasPrefix(binding, []byte(channelBindingPrefix)) {
				t.Fatalf("binding %q does not carry the %q prefix", binding[:24], channelBindingPrefix)
			}

			if got := len(binding) - len(channelBindingPrefix); got != test.wantHash {
				t.Errorf("digest length = %d, want %d", got, test.wantHash)
			}
		})
	}
}

func TestMakeChannelBindingMissingCertificate(t *testing.T) {
	t.Parallel()

	if _, err := makeChannelBinding(tls.ConnectionState{}); err == nil {
		t.Fatal("makeChannelBinding() error = nil, want an error for a connection without a certificate")
	}

	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}}
	if _, err := makeChannelBinding(state); err == nil {
		t.Fatal("makeChannelBinding() error = nil, want an error for a nil certificate")
	}
}

func TestComputeChannelBindingHash(t *testing.T) {
	t.Parallel()

	t.Run("absent binding is sixteen zero bytes", func(t *testing.T) {
		t.Parallel()

		got := computeChannelBindingHash(nil)
		if len(got) != 16 {
			t.Fatalf("length = %d, want 16", len(got))
		}

		if !bytes.Equal(got, make([]byte, 16)) {
			t.Errorf("hash = %x, want sixteen zero bytes", got)
		}
	})

	t.Run("binding is the md5 of the gss structure", func(t *testing.T) {
		t.Parallel()

		binding := []byte("tls-server-end-point:0123456789abcdef0123456789abcdef")

		// Build the expected gss_channel_bindings_struct by hand: four zero
		// words (two address types, two empty lengths), the application data
		// length, then the application data.
		expected := make([]byte, 16)
		expected = binary.LittleEndian.AppendUint32(expected, uint32(len(binding)))
		expected = append(expected, binding...)

		want := md5.Sum(expected) //nolint:gosec // mirrors the protocol.
		if got := computeChannelBindingHash(binding); !bytes.Equal(got, want[:]) {
			t.Errorf("hash = %x, want %x", got, want[:])
		}
	})
}

func TestSPNForHost(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		host string
		want string
	}{
		"host":           {host: "ca.example.com", want: "HTTP/ca.example.com"},
		"host with port": {host: "ca.example.com:8443", want: "HTTP/ca.example.com"},
		"uppercase":      {host: "CA.EXAMPLE.COM", want: "HTTP/ca.example.com"},
		"ipv4":           {host: "192.0.2.10", want: "HTTP/192.0.2.10"},
		"ipv6 with port": {host: "[2001:db8::1]:443", want: "HTTP/2001:db8::1"},
		"empty":          {host: "", want: ""},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := spnForHost(test.host); got != test.want {
				t.Errorf("spnForHost(%q) = %q, want %q", test.host, got, test.want)
			}
		})
	}
}
