package ckhpke

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

func LoadPublicKey(filePath string) (*PublicKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if block.Type != "HPKE PUBLIC KEY" {
		return nil, errors.New("bad type in pem block")
	}

	kem := nameToKEM[block.Headers["KEM"]]
	if kem == 0 {
		return nil, errors.New("bad KEM name in pem block")
	}

	header, err := parsePublicKeyHeader(block.Headers)
	if kem == 0 {
		return nil, fmt.Errorf("error parsing public key header: %w", err)
	}

	key, err := kem.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &PublicKey{
		PublicKey: key,
		KEM:       kem,
		Name:      header.Name,
		Comment:   header.Comment,
	}, nil
}

func SavePublicKey(filePath string, publicKey *PublicKey) error {
	keyBytes, err := publicKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling private key: %w", err)
	}

	header := &publicKeyHeader{
		KEM:     kemToID[publicKey.KEM],
		Name:    publicKey.Name,
		Comment: publicKey.Comment,
	}
	return writePem(filePath, "HPKE PUBLIC KEY", keyBytes, header.Map(), 0644)
}

type PublicKey struct {
	PublicKey kem.PublicKey
	KEM       hpke.KEM
	Name      string
	Comment   string
}

func (k *PublicKey) Key() kem.PublicKey {
	return k.PublicKey
}

func (k *PublicKey) Signature() string {
	bytes, err := k.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	l := len(bytes)
	return hex.EncodeToString(bytes[:4]) + ":" + hex.EncodeToString(bytes[l-4:l])
}

// privateKeyHeader contains information about encryption
// algorithms and parameters used to encrypt a private
// key prior to export or saving to disk.
type publicKeyHeader struct {
	// Name is an optional string representing the name
	// of the user who provisioned the private key.
	Name string
	// Comment is an optional string containing any extra
	// information to associate with the private key.
	Comment string

	// KEM is the name of the key encapsulation mechanism
	// which indicates the algorithm underlying this key.
	KEM string
}

// Map generates the map to pass in as the *pem.Block headers.
func (h *publicKeyHeader) Map() map[string]string {
	m := map[string]string{
		"KEM": h.KEM,
	}

	if h.Name != "" {
		m["Name"] = h.Name
	}
	if h.Comment != "" {
		m["Comment"] = h.Comment
	}

	return m
}

// parsePublicKeyHeader parses *pem.Block headers corresponding to a *publicKeyHeader.
func parsePublicKeyHeader(m map[string]string) (*publicKeyHeader, error) {
	h := &publicKeyHeader{}

	var ok bool
	h.KEM, ok = m["KEM"]
	if !ok || slices.Contains(validKeyAEADs, "KEM") {
		return nil, fmt.Errorf("invalid or missing KEM '%s'", h.KEM)
	}

	return h, nil
}
