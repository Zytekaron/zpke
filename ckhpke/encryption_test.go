package ckhpke

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestEncryptDecrypt(t *testing.T) {
	const kem = hpke.KEM_X25519_HKDF_SHA256
	const kdf = hpke.KDF_HKDF_SHA256
	const aead = hpke.AEAD_AES256GCM

	suite := hpke.NewSuite(kem, kdf, aead)

	pk, sk, err := GenerateKeyPair(kem, "", "")
	if err != nil {
		t.Fatal("error generating key pair:", err)
	}

	ptStr := "Hello, World!"

	pt := strings.NewReader(ptStr)
	ct := &bytes.Buffer{}
	res := &bytes.Buffer{}

	err = Encrypt(ct, pt, suite, pk)
	if err != nil {
		t.Fatal("error encrypting content:", err)
	}

	err = Decrypt(res, ct, sk)
	if err != nil {
		t.Fatal("error decrypting content:", err)
	}

	resStr := res.String()
	if ptStr != resStr {
		t.Fatalf("plaintext and recovered text do not match ('%s' and '%s')\n", ptStr, resStr)
	}
}
