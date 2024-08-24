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

func TestEncryptSave(w io.Writer, r io.Reader, suite hpke.Suite, publicKey *PublicKey) error {
	kem, kdf, aead := suite.Params()
	if kem != publicKey.KEM {
		return ErrMismatchedKEM
	}

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

			encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(sealed)))
			base64.RawURLEncoding.Encode(encoded, sealed)

			// write the output
			nw, ew := w.Write(encoded)
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
