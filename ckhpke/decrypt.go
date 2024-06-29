package ckhpke

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/cloudflare/circl/hpke"
)

func TestLoadDecrypt(w io.Writer, r io.Reader, privateKey *PrivateKey) error {
	scanner := bufio.NewScanner(r)

	// read header data
	header, err := ParseEncryptionHeader(scanner)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}
	if header.KEM != privateKey.KEM {
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
