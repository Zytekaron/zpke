package ckhpke

import (
	"bufio"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
)

type EncryptionHeader struct {
	// Version is the library version that this was encrypted in.
	Version int
	// KEM is the hpke.KEM used for the public/private keypair.
	KEM hpke.KEM
	// KDF is the hpke.KDF used to derive the encryption keu.
	KDF hpke.KDF
	// AEAD is the hpke.AEAD used to encrypt the data.
	AEAD hpke.AEAD
	// EncapKey is the encapsulated key for encryption/decryption.
	EncapKey []byte
}

// ParseEncryptionHeader reads and parses an encryption header
// block from a *bufio.Scanner until reaching a blank line.
func ParseEncryptionHeader(scanner *bufio.Scanner) (*EncryptionHeader, error) {
	header := &EncryptionHeader{}

	parser := NewINIParserFromScanner(scanner)
	ini, err := parser.Parse()
	if err != nil {
		return nil, err
	}

	header.Version, err = ini.Int("version")
	if err != nil {
		return nil, fmt.Errorf("error parsing version: %w", err)
	}

	kemValue := ini.Get("kem")
	header.KEM = nameToKEM[kemValue]
	if header.KEM == 0 {
		return nil, fmt.Errorf("invalid kem value: unknown kem '%s'", kemValue)
	}

	kdfValue := ini.Get("kdf")
	header.KDF = nameToKDF[kdfValue]
	if header.KDF == 0 {
		return nil, fmt.Errorf("invalid kdf value: unknown kdf '%s'", kdfValue)
	}

	aeadValue := ini.Get("aead")
	header.AEAD = nameToAEAD[aeadValue]
	if header.AEAD == 0 {
		return nil, fmt.Errorf("invalid aead value: unknown aead '%s'", aeadValue)
	}

	header.EncapKey, err = ini.GetBase64("encapsulated_key")
	if err != nil {
		return nil, fmt.Errorf("invalid encapsulated key value: %w", err)
	}

	return header, nil
}

func (h *EncryptionHeader) WriteTo(w io.Writer) (int64, error) {
	return h.toINI().WriteTo(w)
}

func (h *EncryptionHeader) Encode() []byte {
	return h.toINI().Bytes()
}

func (h *EncryptionHeader) toINI() *INI {
	ini := &INI{}
	ini.SetInt("version", h.Version)
	ini.Set("kem", kemToName[h.KEM])
	ini.Set("kdf", kdfToName[h.KDF])
	ini.Set("aead", aeadToName[h.AEAD])
	ini.SetBase64("encapsulated_key", h.EncapKey)
	return ini
}
