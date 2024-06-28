package ckhpke

import (
	"errors"
	"fmt"
	"slices"
)

func LoadPublicKey(filePath string) (PublicKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if block.Type != "HPKE PUBLIC KEY" {
		return nil, errors.New("bad type in pem block")
	}

	kem := nameToKEM[block.Headers["KEM"]]
	if kem == 0 {
		return nil, errors.New("bad kem name in pem block")
	}

	key, err := kem.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &publicKeyKEM{
		PublicKey: key,
		kem:       kem,
	}, nil
}

func SavePublicKey(filePath string, publicKey PublicKey) error {
	keyBytes, err := publicKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling private key: %w", err)
	}

	header := &publicKeyHeader{
		KEM: kemToID[publicKey.KEM()],
	}
	return writePem(filePath, "HPKE PUBLIC KEY", keyBytes, header.Map(), 0644)
}

// privateKeyHeader contains information about encryption
// algorithms and parameters used to encrypt a private
// key prior to export or saving to disk.
type publicKeyHeader struct {
	// KEM is the name of the key encapsulation mechanism
	// which indicates the algorithm underlying this key.
	KEM string
}

// Map generates the map to pass in as the *pem.Block headers.
func (h *publicKeyHeader) Map() map[string]string {
	return map[string]string{
		"KEM": h.KEM,
	}
}

// parsePublicKeyHeader parses *pem.Block headers corresponding to a *publicKeyHeader.
func parsePublicKeyHeader(m map[string]string) (*publicKeyHeader, error) {
	h := &publicKeyHeader{}

	var ok bool
	h.KEM, ok = m["KEM"]
	if !ok || slices.Contains(validKeyAEADs, "KEM") {
		return nil, fmt.Errorf("invalid or missing kem '%s'", h.KEM)
	}

	return h, nil
}
