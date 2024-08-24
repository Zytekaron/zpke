package ckhpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// privateKeyEncrypt uses the provided algorithm and parameters to encrypt the key.
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

// privateKeyDecrypt uses the provided algorithm and parameters to decrypt the key.
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
