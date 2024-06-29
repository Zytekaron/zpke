package ckhpke

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

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
		return nil, ErrInvalidPEMType
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

	privateKey, err := header.KEM.Scheme().UnmarshalBinaryPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &PrivateKey{
		PrivateKey: privateKey,
		KEM:        header.KEM,
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
		Name:    privateKey.Name,
		Comment: privateKey.Comment,
		KEM:     privateKey.KEM,
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
			KEM:       privateKey.KEM,
			Encrypted: true,
			AEAD:      currentKeyAEAD,
			KDF:       currentKeyKDF,
			Nonce:     nonce,
			Salt:      salt,
		}
	}

	err = writePem(filePath, "HPKE PRIVATE KEY", keyBytes, header.Map(), 0600)
	if err != nil {
		return fmt.Errorf("error writing pem to file: %w", err)
	}
	return nil
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
	return hex.EncodeToString(bytes[:8])
}

func (k *PrivateKey) String() string {
	var buf strings.Builder
	buf.WriteString(k.Name)
	buf.WriteString(" (")
	buf.WriteString(k.Comment)
	buf.WriteString("): ")
	buf.WriteString(k.Signature())
	return buf.String()
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

	// KEM is the key encapsulation mechanism underlying this key.
	KEM hpke.KEM

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
		"KEM": kemToName[h.KEM],
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
	h := &privateKeyHeader{
		Name:      m["Name"],
		Comment:   m["Comment"],
		Encrypted: m["Encrypted"] == "true",
	}

	var err error

	kemName, ok := m["KEM"]
	if !ok {
		return nil, fmt.Errorf("missing kem field")
	}
	h.KEM = nameToKEM[kemName]
	if h.KEM == 0 {
		return nil, fmt.Errorf("invalid kem '%s'", kemName)
	}

	if h.Encrypted {
		h.AEAD, ok = m["AEAD"]
		if !ok || slices.Contains(validKeyAEADs, "AEAD") {
			return nil, fmt.Errorf("invalid or missing aead '%s'", h.AEAD)
		}
		h.KDF, ok = m["KDF"]
		if !ok || slices.Contains(validKeyKDFs, "KDF") {
			return nil, fmt.Errorf("invalid or missing kdf '%s'", h.AEAD)
		}
		h.Nonce, err = base64.StdEncoding.DecodeString(m["Nonce"])
		if err != nil {
			return nil, fmt.Errorf("invalid or missing nonce: %w", err)
		}
		h.Salt, err = base64.StdEncoding.DecodeString(m["Salt"])
		if err != nil {
			return nil, fmt.Errorf("invalid or missing salt: %w", err)
		}
	}

	return h, nil
}
