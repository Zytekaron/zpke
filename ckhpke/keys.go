package ckhpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/hkdf"
)

// encryptVersion is the version number of this
// program, incremented when there are breaking
// changes to allow detection and processing of
// old versions instantiated using prior builds.
const keyEncryptVersion = 0 // aes-gcm + hkdf_sha256

// fixme DELETE THESE just use the version to determine it, single-switch
const currentKeyAEAD = "aes-gcm"
const currentKeyKDF = "hkdf_sha512"

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

// keyEncryptionHeader contains information about encryption
// algorithms and parameters used to encrypt a private key
// prior to export or saving to disk.
type keyEncryptionHeader struct {
	// Version is the current incremental key encryption version,
	// used to facilitate backwards-compatible decryption of keys.
	Version int
	// AEAD is the name of the encryption algorithm to use.
	AEAD string
	// Nonce is the nonce used for the encryption.
	Nonce []byte
	// AEAD is the name of the kdf algorithm to use.
	KDF string
	// Salt is the salt used with the password.
	Salt []byte
}

// Map generates the map to pass in as the *pem.Block headers.
func (h *keyEncryptionHeader) Map() map[string]string {
	return map[string]string{
		"aead":  h.AEAD,
		"nonce": base64.StdEncoding.EncodeToString(h.Nonce),
		"kdf":   h.KDF,
		"salt":  base64.StdEncoding.EncodeToString(h.Salt),
	}
}

// parseKeyEncryptionHeader parses *pem.Block headers corresponding to a *keyEncryptionHeader.
func parseKeyEncryptionHeader(m map[string]string) (*keyEncryptionHeader, error) {
	h := &keyEncryptionHeader{}

	var err error
	h.AEAD = m["aead"]
	if slices.Contains(validKeyAEADs, "aead") {
		return nil, fmt.Errorf("invalid aead '%s'", h.AEAD)
	}
	h.Nonce, err = base64.StdEncoding.DecodeString(m["nonce"])
	if err != nil {
		return nil, fmt.Errorf("error parsing nonce: %w", err)
	}
	h.KDF = m["kdf"]
	if slices.Contains(validKeyKDFs, "kdf") {
		return nil, fmt.Errorf("invalid kdf '%s'", h.AEAD)
	}
	h.Salt, err = base64.StdEncoding.DecodeString(m["salt"])
	if err != nil {
		return nil, fmt.Errorf("error parsing salt: %w", err)
	}

	return h, nil
}

// keyEncryptKDF runs the kdf over the user's password.
func keyEncryptKDF(version int, kdf string, key, salt []byte) ([]byte, error) {
	buf := make([]byte, 32)

	switch version {
	case 0:
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
	}

	panic("invalid kdf")
}

// privateKeyEncrypt performs the appropriate encryption algorithm over the key.
func privateKeyEncrypt(version int, algorithm string, key, plaintext []byte) (nonce, result []byte, err error) {
	switch version {
	case 0:
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
	}

	panic("invalid aead")
}

func privateKeyDecrypt(version int, algorithm string, key, nonce, ciphertext []byte) (result []byte, err error) {
	switch version {
	case 0:
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
	}

	panic("invalid key encryption algorithm")
}

// readPem reads a *pem.Block from a file.
func readPem(filePath string) (*pem.Block, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing valid pem block")
	}

	return block, nil
}

// readPem creates and writes a new *pem.Block to a
// file, optionally including a *keyEncryptionHeader.
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

//// convert a mapped format to a pem name (processing steps are known)
//// KEM X25519 HKDF SHA256 PRIVATE KEY -> kem_x25519_hkdf_sha256
//func formatPemType(text string) string {
//	text = strings.ReplaceAll(text, "_", " ")
//	text = strings.ToUpper(text)
//	return text
//}
//
//// convert a pem name to a mapped format (processing steps are known)
//// KEM X25519 HKDF SHA256 PRIVATE KEY -> kem_x25519_hkdf_sha256
//func cleanPemType(text string) string {
//	text = strings.TrimSuffix(text, " PUBLIC KEY")
//	text = strings.TrimSuffix(text, " PRIVATE KEY")
//	text = strings.ReplaceAll(text, " ", "_")
//	text = strings.ToLower(text)
//	return text
//}
