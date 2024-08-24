package ckhpke

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestGenerateKeyPair(t *testing.T) {
	const kem = hpke.KEM_X25519_HKDF_SHA256
	const name = "Bob"
	const comment = "Bob's HPKE key pair"

	pk, sk, err := GenerateKeyPair(kem, name, comment)
	if err != nil {
		t.Fatalf("error generating key: %s\n", err)
	}

	if pk.KEM != kem {
		t.Error("public key has wrong kem")
	}
	if sk.KEM != kem {
		t.Error("private key has wrong kem")
	}

	if pk.Name != name || pk.Comment != comment {
		t.Errorf("public key has wrong name/comment")
	}
	if sk.Name != name || sk.Comment != comment {
		t.Errorf("private key has wrong name/comment")
	}
}
