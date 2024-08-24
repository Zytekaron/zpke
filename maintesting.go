package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/zytekaron/zpke/ckhpke"
)

const kem = hpke.KEM_X25519_HKDF_SHA256
const kdf = hpke.KDF_HKDF_SHA256
const aead = hpke.AEAD_ChaCha20Poly1305

const bufferSize = 4096

func main() {
	encryptedBufferSize := int(aead.CipherLen(bufferSize))
	fmt.Println(bufferSize, encryptedBufferSize)

	suite := hpke.NewSuite(kem, kdf, aead)

	pk, sk, err := ckhpke.GenerateKeyPair(kem, "", "")
	if err != nil {
		log.Fatalln("gen keys:", err)
	}

	// for encrypt
	sender, err := suite.NewSender(pk.Key(), nil)
	if err != nil {
		log.Fatalln("new sender:", err)
	}
	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		log.Fatalln("setup sender:", err)
	}
	// for decrypt
	receiver, err := suite.NewReceiver(sk.Key(), nil)
	if err != nil {
		log.Fatalln("creating receiver:", err)
	}
	opener, err := receiver.Setup(encapsulatedKey)
	if err != nil {
		log.Fatalln("setting up receiver:", err)
	}

	inputForLater := &bytes.Buffer{}
	input := &bytes.Buffer{}
	middle := &bytes.Buffer{}
	output := &bytes.Buffer{}

	for i := 0; i < 123456; i++ {
		input.WriteByte(byte(i % 256))
		inputForLater.WriteByte(byte(i % 256))
	}

	nw, err := encryptStream(middle, input, sealer, bufferSize)
	if err != nil {
		log.Fatalln("err encrypt:", err)
	}

	fmt.Println("nw:", nw)
	//fmt.Println("middle:", middle.Bytes(), middle.Len(), middle.Cap())

	nw, err = decryptStream(output, middle, opener, encryptedBufferSize)
	if err != nil {
		log.Fatalln("err decrypt:", err)
	}

	fmt.Println("nw:", nw)
	//fmt.Println("ok done", output.Bytes(), output.Len(), output.Cap())
	fmt.Println("output ok?", slices.Equal(inputForLater.Bytes(), output.Bytes()))
}

func encryptStream(w io.Writer, r io.Reader, sealer hpke.Sealer, bufferSize int) (int, error) {
	var err error
	bytesWritten := 0
	buf := make([]byte, bufferSize)
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

			// write the output
			nw, ew := w.Write(sealed)
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

func decryptStream(w io.Writer, r io.Reader, opener hpke.Opener, encryptedBufferSize int) (int, error) {
	var err error
	bytesWritten := 0
	readerBuf := make([]byte, encryptedBufferSize)
	for {
		nr, er := r.Read(readerBuf)

		// if the buffer is not empty, decrypt and write to output
		if nr > 0 {
			// decrypt contents with opener
			opened, e := opener.Open(readerBuf[:nr], nil)
			if e != nil {
				err = fmt.Errorf("error opening: %w", e)
				break
			}

			// write decrypted contents
			nw, ew := w.Write(opened)
			bytesWritten += nw
			if err != nil {
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
