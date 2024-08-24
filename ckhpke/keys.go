package ckhpke

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/hkdf"
)

const currentKeyAEAD = "aes-gcm"
const currentKeyKDF = "hkdf_sha512"

var ErrInvalidSeedLength = errors.New("invalid seed length for kem")
var ErrInvalidPEMType = errors.New("invalid type in pem block")
var ErrInvalidKDF = errors.New("invalid kdf identifier")
var ErrInvalidAEAD = errors.New("invalid aead identifier")
var ErrMismatchedKEM = errors.New("the key does not match the provided KEM")

// GenerateKeyPair generates a key pair based on the provided hpke.KEM.
func GenerateKeyPair(kem hpke.KEM, name, comment string) (*CKPublicKey, *CKPrivateKey, error) {
	publicKey, privateKey, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key pair: %w", err)
	}

	pk := &CKPublicKey{
		PublicKey: publicKey,
		KEM:       kem,
		Name:      name,
		Comment:   comment,
	}
	sk := &CKPrivateKey{
		PrivateKey: privateKey,
		KEM:        kem,
		Name:       name,
		Comment:    comment,
	}
	return pk, sk, nil
}

// GenerateKeyPairFromSeed generates a key pair based on the provided hpke.KEM and seed.
//
// The seed slice must be the correct length for the KEM, kem.Scheme().SeedSize().
func GenerateKeyPairFromSeed(kem hpke.KEM, seed []byte, name, comment string) (*CKPublicKey, *CKPrivateKey, error) {
	scheme := kem.Scheme()
	if len(seed) != scheme.SeedSize() {
		return nil, nil, ErrInvalidSeedLength
	}

	publicKey, privateKey := scheme.DeriveKeyPair(seed)

	pk := &CKPublicKey{
		PublicKey: publicKey,
		KEM:       kem,
		Name:      name,
		Comment:   comment,
	}
	sk := &CKPrivateKey{
		PrivateKey: privateKey,
		KEM:        kem,
		Name:       name,
		Comment:    comment,
	}
	return pk, sk, nil
}

// keyEncryptKDF runs the kdf over the user's password.
func keyEncryptKDF(kdf string, key, salt []byte) ([]byte, error) {
	buf := make([]byte, 32)

	switch kdf {
	case "hkdf_sha256":
		hk := hkdf.New(sha256.New, key, salt, nil)
		_, err := hk.Read(buf)
		return buf, err
	case "hkdf_sha384":
		hk := hkdf.New(sha512.New384, key, salt, nil)
		_, err := hk.Read(buf)
		return buf, err
	case "hkdf_sha512":
		hk := hkdf.New(sha512.New, key, salt, nil)
		_, err := hk.Read(buf)
		return buf, err
	}

	return nil, ErrInvalidKDF
}

// readPem reads a *pem.Block from a file.
func readPem(filePath string) (*pem.Block, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing or valid pem block")
	}

	return block, nil
}

// readPem creates and writes a new *pem.Block to a
// file, optionally including a *privateKeyHeader.
func writePem(filePath, pemType string, keyBytes []byte, headerMap map[string]string, perm os.FileMode) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:    pemType,
		Headers: headerMap,
		Bytes:   keyBytes,
	})
	if err != nil {
		return fmt.Errorf("error writing pem block: %w", err)
	}
	return nil
}
