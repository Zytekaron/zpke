package ckhpke

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
)

// encryptVersion is the version number of this
// program, incremented when there are breaking
// changes to allow detection and processing of
// old versions instantiated using prior builds.
const encryptVersion = -1 // no defined format for version -1

// encryptBufferSize is the buffer size used for
// chunking input files/streams for encryption.
// the buffer reads in this many bytes, encrypts,
// encodes to base64, and writes to the output stream.
const encryptBufferSize = 4096

// Encrypt encrypts a stream of content given a hpke.Suite and a *CKPublicKey.
func Encrypt(w io.Writer, r io.Reader, suite hpke.Suite, publicKey *CKPublicKey) error {
	kem, kdf, aead := suite.Params()
	if kem != publicKey.KEM {
		return ErrMismatchedKEM
	}

	// create a new sender and sealer context for the message
	sender, err := suite.NewSender(publicKey.Key(), nil)
	if err != nil {
		return fmt.Errorf("error creating sender: %w", err)
	}
	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return fmt.Errorf("error setting up sender: %w", err)
	}

	header := EncryptionHeader{
		Version:  encryptVersion,
		KEM:      kem,
		KDF:      kdf,
		AEAD:     aead,
		EncapKey: encapsulatedKey,
	}
	_, err = w.Write(header.Encode())
	if err != nil {
		return fmt.Errorf("error writing to output file: %w", err)
	}

	_, err = w.Write([]byte("\n"))
	if err != nil {
		return fmt.Errorf("error writing to output file: %w", err)
	}

	_, err = encryptToWriter(w, r, sealer)
	if err != nil {
		return fmt.Errorf("error encrypting: %w", err)
	}

	return nil
}

func encryptToWriter(w io.Writer, r io.Reader, sealer hpke.Sealer) (int, error) {
	// calculate the size of the ciphertext based on the buffer length,
	// then use it to create a buffer for base64 encoded output.
	_, _, aead := sealer.Suite().Params()
	bufLen := int(aead.CipherLen(encryptBufferSize))
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(bufLen))

	var err error
	bytesWritten := 0
	buf := make([]byte, encryptBufferSize)
	for {
		// read buffer size bytes into buffer
		nr, er := r.Read(buf)

		// if the buffer is not empty, encrypt and write to output
		if nr > 0 {
			// encrypt the data into a new buffer
			sealed, es := sealer.Seal(buf[:nr], nil)
			if es != nil {
				err = fmt.Errorf("error sealing data: %w", es)
				break
			}

			// slice the output buffer here for the last pass in case the
			// sealed buffer length won't fill len(encoded) after encoding.
			encodedLen := base64.RawURLEncoding.EncodedLen(len(sealed))
			encodedSlice := encoded[:encodedLen]

			base64.RawURLEncoding.Encode(encodedSlice, sealed)

			// write the output
			nw, ew := w.Write(encodedSlice)
			bytesWritten += nw
			if ew != nil {
				err = ew
				break
			}

			// write a separator
			nw, ew = w.Write([]byte{'\n'})
			bytesWritten += nw
			if ew != nil {
				err = ew
				break
			}
		}

		// if there was a read error, finish here
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return bytesWritten, err
}
