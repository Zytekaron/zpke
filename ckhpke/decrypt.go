package ckhpke

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/hpke"
)

func TestLoadDecrypt(w io.Writer, r io.Reader, privateKey PrivateKey) error {
	scanner := bufio.NewScanner(r)

	// read header data
	header, err := readHeader(scanner)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}
	if header.KEM != privateKey.KEM() {
		return ErrMismatchedKEM
	}

	suite := hpke.NewSuite(header.KEM, header.KDF, header.AEAD)

	receiver, err := suite.NewReceiver(privateKey.Key(), nil)
	if err != nil {
		log.Fatalln("creating receiver:", err)
	}
	opener, err := receiver.Setup(header.EncapKey)
	if err != nil {
		log.Fatalln("setting up receiver:", err)
	}

	var decodeBuf []byte
	for scanner.Scan() {
		bytes := scanner.Bytes()
		if len(bytes) == 0 {
			continue
		}

		// calculate buffer size, create on first line
		decodedLen := base64.RawURLEncoding.DecodedLen(len(bytes))
		if decodeBuf == nil {
			decodeBuf = make([]byte, decodedLen)
		}

		// decode line
		buf := decodeBuf[:decodedLen]
		_, err := base64.RawURLEncoding.Decode(buf, bytes)
		if err != nil {
			return err
		}

		// decrypt contents with opener
		opened, err := opener.Open(buf, nil)
		if err != nil {
			return fmt.Errorf("error opening: %w", err)
		}

		// write decrypted contents
		_, err = w.Write(opened)
		if err != nil {
			return err
		}
	}
	err = scanner.Err()
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	return nil
}

func readHeader(scanner *bufio.Scanner) (*Header, error) {
	header := &Header{}

	// parse version line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok := parseLine(scanner.Text())
	if !ok || label != "version" {
		return nil, errors.New("invalid version line")
	}
	version, err := strconv.Atoi(value)
	if err != nil {
		return nil, fmt.Errorf("invalid version value: %w", err)
	}
	header.Version = version

	// parse kem line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "kem" {
		return nil, errors.New("invalid kem line")
	}
	kem := nameToKEM[value]
	if kem == 0 {
		return nil, fmt.Errorf("invalid kem value: unknown kem '%s'", value)
	}
	header.KEM = kem

	// parse kem line
	if !scanner.Scan() {
		return nil, io.ErrUnexpectedEOF
	}
	label, value, ok = parseLine(scanner.Text())
	if !ok || label != "kdf" {
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
	if !ok || label != "aead" {
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
	if !ok || label != "encapsulated_key" {
		return nil, errors.New("invalid encapsulated key line")
	}
	encapKey, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid encapsulated key value: %w", err)
	}
	header.EncapKey = encapKey

	return header, nil
}

func parseLine(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	label, value := parts[0], parts[1]
	label = strings.TrimSpace(label)
	label = strings.ToLower(label)
	value = strings.TrimSpace(value)
	return label, value, true
}
