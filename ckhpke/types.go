package ckhpke

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

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

	// parse version line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok := parseLine(scanner.Text())
	if !ok || label != "Version" {
		return nil, errors.New("invalid version line")
	}
	version, err := strconv.Atoi(value)
	if err != nil {
		return nil, fmt.Errorf("invalid version value: %w", err)
	}
	header.Version = version

	// parse KEM line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "KEM" {
		return nil, errors.New("invalid kem line")
	}
	kem := nameToKEM[value]
	if kem == 0 {
		return nil, fmt.Errorf("invalid kem value: unknown kem '%s'", value)
	}
	header.KEM = kem

	// parse KEM line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "KDF" {
		return nil, errors.New("invalid kdf line")
	}
	kdf := nameToKDF[value]
	if kem == 0 {
		return nil, fmt.Errorf("invalid kdf value: unknown kdf '%s'", value)
	}
	header.KDF = kdf

	// parse aead line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "AEAD" {
		return nil, errors.New("invalid aead line")
	}
	aead := nameToAEAD[value]
	if aead == 0 {
		return nil, fmt.Errorf("invalid aead value: unknown aead '%s'", value)
	}
	header.AEAD = aead

	// parse encapsulated key line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "EncapsulatedKey" {
		return nil, errors.New("invalid encapsulated key line")
	}
	encapKey, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid encapsulated key value: %w", err)
	}
	header.EncapKey = encapKey

	return header, nil
}

func (h *EncryptionHeader) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h.Encode())
	return int64(n), err
}

func (h *EncryptionHeader) Encode() []byte {
	var buf bytes.Buffer

	buf.WriteString("Version: ")
	buf.WriteString(strconv.Itoa(h.Version))

	buf.WriteString("\nKEM: ")
	buf.WriteString(kemToName[h.KEM])

	buf.WriteString("\nKDF: ")
	buf.WriteString(kdfToName[h.KDF])

	buf.WriteString("\nAEAD: ")
	buf.WriteString(aeadToName[h.AEAD])

	buf.WriteString("\nEncapsulatedKey: ")
	buf.WriteString(base64.RawURLEncoding.EncodeToString(h.EncapKey))

	buf.WriteString("\n")
	return buf.Bytes()
}
