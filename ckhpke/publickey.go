package ckhpke

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

func LoadPublicKey(filePath string) (*PublicKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if block.Type != "HPKE PUBLIC KEY" {
		return nil, ErrInvalidPEMType
	}

	kemName := nameToKEM[block.Headers["KEM"]]
	if kemName == 0 {
		return nil, errors.New("bad kem name in pem block")
	}

	header, err := parsePublicKeyHeader(block.Headers)
	if kemName == 0 {
		return nil, fmt.Errorf("error parsing public key header: %w", err)
	}

	publicKey, err := kemName.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key bytes: %w", err)
	}

	return &PublicKey{
		PublicKey: publicKey,
		KEM:       kemName,
		Name:      header.Name,
		Comment:   header.Comment,
	}, nil
}

func SavePublicKey(filePath string, publicKey *PublicKey) error {
	keyBytes, err := publicKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling public key: %w", err)
	}

	header := &publicKeyHeader{
		KEM:     publicKey.KEM,
		Name:    publicKey.Name,
		Comment: publicKey.Comment,
	}
	err = writePem(filePath, "HPKE PUBLIC KEY", keyBytes, header.Map(), 0644)
	if err != nil {
		return fmt.Errorf("error writing pem to file: %w", err)
	}
	return nil
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
	return hex.EncodeToString(bytes[:8])
}

func (k *PublicKey) String() string {
	var buf strings.Builder
	buf.WriteString(k.Name)
	buf.WriteString(" (")
	buf.WriteString(k.Comment)
	buf.WriteString("): ")
	buf.WriteString(k.Signature())
	return buf.String()
}

// publicKeyHeader contains information about a public key.
type publicKeyHeader struct {
	// Name is an optional string representing the name
	// of the user who provisioned the private key.
	Name string
	// Comment is an optional string containing any extra
	// information to associate with the private key.
	Comment string

	// KEM is the key encapsulation mechanism underlying this key.
	KEM hpke.KEM
}

// Map generates the map to pass in as the *pem.Block headers.
func (h *publicKeyHeader) Map() map[string]string {
	m := map[string]string{
		"KEM": kemToName[h.KEM],
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
	h := &publicKeyHeader{
		Name:    m["Name"],
		Comment: m["Comment"],
	}

	kemName, ok := m["KEM"]
	if !ok {
		return nil, fmt.Errorf("missing kem field")
	}
	h.KEM = nameToKEM[kemName]
	if h.KEM == 0 {
		return nil, fmt.Errorf("invalid kem '%s'", kemName)
	}

	return h, nil
}
