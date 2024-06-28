package ckhpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/hkdf"
)

const currentKeyAEAD = "aes-gcm"
const currentKeyKDF = "hkdf_sha512"

var ErrInvalidKDF = errors.New("invalid kdf identifier")
var ErrInvalidAEAD = errors.New("invalid aead identifier")

// GenerateKeyPair generates a key pair based on the provided hpke.KEM.
func GenerateKeyPair(kem hpke.KEM) (PublicKey, PrivateKey, error) {
	publicKey, privateKey, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generating key pair: %w", err)
	}

	pk := &publicKeyKEM{
		PublicKey: publicKey,
		kem:       kem,
	}
	sk := &privateKeyKEM{
		PrivateKey: privateKey,
		kem:        kem,
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

// privateKeyEncrypt performs the appropriate encryption algorithm over the key.
func privateKeyEncrypt(algorithm string, key, plaintext []byte) (nonce, result []byte, err error) {
	switch algorithm {
	case "aes-gcm":
		// create block and gcm
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating aes cipher: %w", err)
		}
		c, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating gcm: %w", err)
		}

		// generate nonce
		nonce := make([]byte, c.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading random data: %w", err)
		}

		// encrypt key into new buffer
		result := c.Seal(nil, nonce, plaintext, nil)
		return nonce, result, nil
	}

	return nil, nil, ErrInvalidAEAD
}

func privateKeyDecrypt(algorithm string, key, nonce, ciphertext []byte) (result []byte, err error) {
	switch algorithm {
	case "aes-gcm":
		// create block and gcm
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("error creating aes cipher: %w", err)
		}
		c, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("error creating gcm: %w", err)
		}

		// encrypt key into new buffer
		result, err := c.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("error opening: %w", err)
		}

		return result, nil
	}

	return nil, ErrInvalidAEAD
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
