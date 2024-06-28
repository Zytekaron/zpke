package ckhpke

import (
	"errors"
	"fmt"
	"strings"
)

func LoadPublicKey(filePath string) (PublicKey, error) {
	block, err := readPem(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading pem file: %w", err)
	}
	if !strings.HasSuffix(block.Type, " PUBLIC KEY") {
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

	pemType := formatPemType(kemToID[publicKey.KEM()]) + " PUBLIC KEY"
	return writePem(filePath, pemType, keyBytes, nil, 0644)
}
