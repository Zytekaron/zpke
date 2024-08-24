package ckhpke

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"github.com/cloudflare/circl/hpke"
)

// Decrypt decrypts a stream of content given a *CKPrivateKey.
func Decrypt(w io.Writer, r io.Reader, privateKey *CKPrivateKey) error {
	scanner := bufio.NewScanner(r)

	// read ini header (followed by a single blank line)
	headerText := &bytes.Buffer{}
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			break
		}

		headerText.WriteString(text)
		headerText.WriteString("\n")
	}

	// read header data
	header, err := ParseEncryptionHeader(headerText)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}
	if header.KEM != privateKey.KEM {
		return ErrMismatchedKEM
	}

	suite := hpke.NewSuite(header.KEM, header.KDF, header.AEAD)

	// create a new receiver and opener context for the message
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
		b := scanner.Bytes()
		if len(b) == 0 {
			continue
		}

		// calculate buffer size, create on first line
		decodedLen := base64.RawURLEncoding.DecodedLen(len(b))
		if decodeBuf == nil {
			decodeBuf = make([]byte, decodedLen)
		}

		// decode line
		buf := decodeBuf[:decodedLen]
		_, err := base64.RawURLEncoding.Decode(buf, b)
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
