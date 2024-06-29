package ckhpke

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

var validKeyAEADs = []string{"aes-gcm"}
var validKeyKDFs = []string{"hkdf_sha512"}

func LoadPrivateKey(filePath string, key []byte) (*PrivateKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if block.Type != "HPKE PRIVATE KEY" {
		return nil, errors.New("bad type in pem block")
	}

	kem := nameToKEM[block.Headers["KEM"]]
	if kem == 0 {
		return nil, errors.New("bad KEM name in pem block")
	}

	header, err := parsePrivateKeyHeader(block.Headers)
	if err != nil {
		return nil, fmt.Errorf("error parsing headers: %w", err)
	}

	keyBytes := block.Bytes

	if header.Encrypted {
		hash, err := keyEncryptKDF(header.KDF, key, header.Salt)
		if err != nil {
			return nil, fmt.Errorf("error executing kdf: %w", err)
		}

		decryptedKeyBytes, err := privateKeyDecrypt(header.AEAD, hash, header.Nonce, keyBytes)
		if err != nil {
			return nil, fmt.Errorf("error encrypting key: %w", err)
		}

		keyBytes = decryptedKeyBytes
	}

	privateKey, err := kem.Scheme().UnmarshalBinaryPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &PrivateKey{
		PrivateKey: privateKey,
		KEM:        kem,
		Name:       header.Name,
		Comment:    header.Comment,
	}, nil
}

func SavePrivateKey(filePath string, privateKey *PrivateKey, key []byte) error {
	keyBytes, err := privateKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling private key: %w", err)
	}

	header := &privateKeyHeader{
		KEM: kemToID[privateKey.KEM],
	}
	if key != nil {
		salt := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, salt)
		if err != nil {
			return fmt.Errorf("error generating salt: %w", err)
		}

		hash, err := keyEncryptKDF(currentKeyKDF, key, salt)
		if err != nil {
			return fmt.Errorf("error executing kdf: %w", err)
		}

		nonce, encryptedKeyBytes, err := privateKeyEncrypt(currentKeyAEAD, hash, keyBytes)
		if err != nil {
			return fmt.Errorf("error encrypting key: %w", err)
		}
		keyBytes = encryptedKeyBytes

		header = &privateKeyHeader{
			Name:      privateKey.Name,
			Comment:   privateKey.Comment,
			KEM:       kemToID[privateKey.KEM],
			Encrypted: true,
			AEAD:      currentKeyAEAD,
			KDF:       currentKeyKDF,
			Nonce:     nonce,
			Salt:      salt,
		}
	}

	return writePem(filePath, "HPKE PRIVATE KEY", keyBytes, header.Map(), 0600)
}

type PrivateKey struct {
	PrivateKey kem.PrivateKey
	KEM        hpke.KEM
	Name       string
	Comment    string
}

func (k *PrivateKey) Key() kem.PrivateKey {
	return k.PrivateKey
}

func (k *PrivateKey) Signature() string {
	bytes, err := k.PrivateKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	l := len(bytes)
	return hex.EncodeToString(bytes[:4]) + ":" + hex.EncodeToString(bytes[l-4:l])
}

// privateKeyHeader contains information about encryption
// algorithms and parameters used to encrypt a private
// key prior to export or saving to disk.
type privateKeyHeader struct {
	// Name is an optional string representing the name
	// of the user who provisioned the private key.
	Name string
	// Comment is an optional string containing any extra
	// information to associate with the private key.
	Comment string

	// KEM is the name of the key encapsulation mechanism
	// which indicates the algorithm underlying this key.
	KEM string

	// Encrypted flags whether this key is encrypted.
	// If true, headers relating to encryption should be read.
	Encrypted bool

	// AEAD is the name of the algorithm used to encrypt this key.
	AEAD string
	// KDF is the name of the key derivation function for encryption.
	KDF string
	// Nonce is used with the AEAD to encrypt this key.
	Nonce []byte
	// Salt is used with the KDF to derive the key for encryption.
	Salt []byte
}

// Map generates the map to pass in as the *pem.Block headers.
func (h *privateKeyHeader) Map() map[string]string {
	m := map[string]string{
		"KEM": h.KEM,
	}

	if h.Name != "" {
		m["Name"] = h.Name
	}
	if h.Comment != "" {
		m["Comment"] = h.Comment
	}

	if h.Encrypted {
		m["Encrypted"] = "true"
		m["AEAD"] = h.AEAD
		m["KDF"] = h.KDF
		m["Nonce"] = base64.StdEncoding.EncodeToString(h.Nonce)
		m["Salt"] = base64.StdEncoding.EncodeToString(h.Salt)
	}

	return m
}

// parsePrivateKeyHeader parses *pem.Block headers corresponding to a *privateKeyHeader.
func parsePrivateKeyHeader(m map[string]string) (*privateKeyHeader, error) {
	h := &privateKeyHeader{}

	var err error
	var ok bool

	h.KEM, ok = m["KEM"]
	if !ok || slices.Contains(validKeyAEADs, "KEM") {
		return nil, fmt.Errorf("invalid or missing KEM '%s'", h.KEM)
	}

	if m["Encrypted"] == "true" {
		h.Encrypted = true

		h.AEAD, ok = m["AEAD"]
		if !ok || slices.Contains(validKeyAEADs, "AEAD") {
			return nil, fmt.Errorf("invalid or missing aead '%s'", h.AEAD)
		}
		h.Nonce, err = base64.StdEncoding.DecodeString(m["Nonce"])
		if err != nil {
			return nil, fmt.Errorf("invalid or missing nonce: %w", err)
		}
		h.KDF, ok = m["KDF"]
		if !ok || slices.Contains(validKeyKDFs, "KDF") {
			return nil, fmt.Errorf("invalid or missing kdf '%s'", h.AEAD)
		}
		h.Salt, err = base64.StdEncoding.DecodeString(m["Salt"])
		if err != nil {
			return nil, fmt.Errorf("invalid or missing salt: %w", err)
		}
	}

	return h, nil
}
