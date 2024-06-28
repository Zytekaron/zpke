package ckhpke

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

var validKeyAEADs = []string{"aes-gcm"}
var validKeyKDFs = []string{"hkdf_sha512"}

func LoadPrivateKey(filePath string) (PrivateKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if !strings.HasSuffix(block.Type, " PRIVATE KEY") {
		return nil, errors.New("bad type in pem block")
	}

	kem := nameToKEM[cleanPemType(block.Type)]
	if kem == 0 {
		return nil, errors.New("bad kem name in pem block")
	}

	privateKey, err := kem.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &privateKeyKEM{
		PrivateKey: privateKey,
		kem:        kem,
	}, nil
}

func LoadEncryptedPrivateKey(filePath string, key []byte) (PrivateKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if !strings.HasSuffix(block.Type, " PRIVATE KEY") {
		return nil, errors.New("bad type in pem block")
	}

	kem := nameToKEM[cleanPemType(block.Type)]
	if kem == 0 {
		return nil, errors.New("bad kem name in pem block")
	}

	keyBytes := block.Bytes
	// fixme determine the best way to determine the presence of encryption
	// (options include: len(headers), len(key), attempt to parse)
	if len(block.Headers) != 0 {
		header, err := parseKeyEncryptionHeader(block.Headers)
		if err != nil {
			return nil, fmt.Errorf("error parsing headers: %w", err)
		}

		hash, err := keyEncryptKDF(keyEncryptVersion, currentKeyKDF, key, header.Salt)
		if err != nil {
			return nil, fmt.Errorf("error executing kdf: %w", err)
		}

		result, err := privateKeyDecrypt(keyEncryptVersion, currentKeyAEAD, hash, header.Nonce, keyBytes)
		if err != nil {
			return nil, fmt.Errorf("error encrypting key: %w", err)
		}
		keyBytes = result
	}

	privateKey, err := kem.Scheme().UnmarshalBinaryPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key bytes: %w", err)
	}

	return &privateKeyKEM{
		PrivateKey: privateKey,
		kem:        kem,
	}, nil
}

func SavePrivateKey(filePath string, privateKey PrivateKey) error {
	keyBytes, err := privateKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling private key: %w", err)
	}

	pemType := formatPemType(kemToID[privateKey.KEM()]) + " PRIVATE KEY"
	return writePem(filePath, pemType, keyBytes, nil, 0600)
}

func SaveEncryptedPrivateKey(filePath string, privateKey PrivateKey, key []byte) error {
	keyBytes, err := privateKey.Key().MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling private key: %w", err)
	}

	salt := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	hash, err := keyEncryptKDF(keyEncryptVersion, currentKeyKDF, key, salt)
	if err != nil {
		return fmt.Errorf("error executing kdf: %w", err)
	}

	nonce, encryptedKeyBytes, err := privateKeyEncrypt(keyEncryptVersion, currentKeyAEAD, hash, keyBytes)
	if err != nil {
		return fmt.Errorf("error encrypting key: %w", err)
	}
	header := &keyEncryptionHeader{
		Version: keyEncryptVersion,
		AEAD:    currentKeyAEAD,
		Nonce:   nonce,
		KDF:     currentKeyKDF,
		Salt:    salt,
	}

	pemType := formatPemType(kemToID[privateKey.KEM()]) + " PRIVATE KEY"
	return writePem(filePath, pemType, encryptedKeyBytes, header, 0600)
}
