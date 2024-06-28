package ckhpke

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type Header struct {
	// Version is the library version that this was encrypted in.
	Version int `json:"version"`
	// KEM is the hpke.KEM used for the public/private keypair.
	KEM hpke.KEM `json:"kem"`
	// KDF is the hpke.KDF used to derive the encryption keu.
	KDF hpke.KDF `json:"kdf"`
	// AEAD is the hpke.AEAD used to encrypt the data.
	AEAD hpke.AEAD `json:"aead"`
	// EncapKey is the encapsulated key for encryption/decryption.
	EncapKey []byte `json:"encap_key"`
}

func (h *Header) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h.Encode())
	return int64(n), err
}

func (h *Header) Encode() []byte {
	var buf bytes.Buffer

	buf.WriteString("version: ")
	buf.WriteString(strconv.Itoa(h.Version))

	buf.WriteString("\nkem: ")
	buf.WriteString(kemToID[h.KEM])

	buf.WriteString("\nkdf: ")
	buf.WriteString(kdfToID[h.KDF])

	buf.WriteString("\naead: ")
	buf.WriteString(aeadToID[h.AEAD])

	buf.WriteString("\nencapsulated_key: ")
	buf.WriteString(base64.RawURLEncoding.EncodeToString(h.EncapKey))

	buf.WriteString("\n")
	return buf.Bytes()
}

type PublicKey interface {
	Key() kem.PublicKey
	KEM() hpke.KEM
	Signature() string
}

type PrivateKey interface {
	Key() kem.PrivateKey
	KEM() hpke.KEM
	Signature() string
}

type publicKeyKEM struct {
	kem.PublicKey
	kem hpke.KEM
}

func (k *publicKeyKEM) KEM() hpke.KEM {
	return k.kem
}

func (k *publicKeyKEM) Key() kem.PublicKey {
	return k.PublicKey
}

func (k *publicKeyKEM) Signature() string {
	bytes, err := k.MarshalBinary()
	if err != nil {
		panic(err)
	}
	l := len(bytes)
	return hex.EncodeToString(bytes[:4]) + ":" + hex.EncodeToString(bytes[l-4:l])
}

type privateKeyKEM struct {
	kem.PrivateKey
	kem hpke.KEM
}

func (k *privateKeyKEM) KEM() hpke.KEM {
	return k.kem
}

func (k *privateKeyKEM) Key() kem.PrivateKey {
	return k.PrivateKey
}

func (k *privateKeyKEM) Signature() string {
	bytes, err := k.MarshalBinary()
	if err != nil {
		panic(err)
	}
	l := len(bytes)
	return hex.EncodeToString(bytes[:4]) + ":" + hex.EncodeToString(bytes[l-4:l])
}
