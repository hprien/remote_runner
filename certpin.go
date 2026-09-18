package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// fingerprint returns the SHA-256 fingerprint of a DER encoded certificate.
func fingerprint(der []byte) [sha256.Size]byte {
	return sha256.Sum256(der)
}

// loadCertFingerprint reads a PEM encoded certificate file and returns the
// SHA-256 fingerprint of the certificate it contains. Certificates are pinned
// by comparing fingerprints, no CA validation takes place.
func loadCertFingerprint(path string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return zero, fmt.Errorf("certificate %s: no PEM block found", path)
	}
	if block.Type != "CERTIFICATE" {
		return zero, fmt.Errorf("certificate %s: unexpected PEM block type %q", path, block.Type)
	}
	return fingerprint(block.Bytes), nil
}

// pinnedPeer reports whether the certificate presented by the peer is the
// pinned certificate.
func pinnedPeer(peerCerts []*x509.Certificate, pin [sha256.Size]byte) bool {
	if len(peerCerts) == 0 {
		return false
	}
	return fingerprint(peerCerts[0].Raw) == pin
}

// pinVerifier returns a tls.Config VerifyPeerCertificate callback that only
// accepts the pinned certificate.
func pinVerifier(pin [sha256.Size]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no server certificate presented")
		}
		if fingerprint(rawCerts[0]) != pin {
			return errors.New("server certificate does not match pin")
		}
		return nil
	}
}
