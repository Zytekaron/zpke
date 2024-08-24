package ckhpke

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestCleanUserInput(t *testing.T) {
	tests := []struct {
		before, expect string
	}{
		{" p384_hkdf_sha384  ", "p384_hkdf_sha384"},                   // trailing spaces
		{"HKDF_SHA256", "hkdf_sha256"},                                // uppercase letters
		{"AES-256-GCM", "aes256gcm"},                                  // extra hyphens
		{"KEM_X25519-Kyber768-DRAFT00 ", "kem_x25519kyber768draft00"}, // combined
	}

	for i, test := range tests {
		result := cleanUserInput(test.before)
		if result != test.expect {
			t.Errorf("test %d failed: expected '%s' but got '%s'\n", i+1, test.expect, result)
		}
	}
}

func TestFindKEM(t *testing.T) {
	tests := []struct {
		before string
		expect hpke.KEM
	}{
		// official names
		{"p256_hkdf_sha256", hpke.KEM_P256_HKDF_SHA256},
		{"x25519_hkdf_sha256", hpke.KEM_X25519_HKDF_SHA256},
		// alternate names
		{"KEM_P384_HKDF_SHA384", hpke.KEM_P384_HKDF_SHA384},
		{"X25519Kyber768draft00", hpke.KEM_X25519_KYBER768_DRAFT00},
		// ids
		{"0x21", hpke.KEM_X448_HKDF_SHA512},
		{"0x12", hpke.KEM_P521_HKDF_SHA512},
	}

	for i, test := range tests {
		result := FindKEM(test.before)
		if result != test.expect {
			t.Errorf("test %d failed: expected '%d' but got '%d'\n", i+1, test.expect, result)
		}
	}
}

func TestFindKDF(t *testing.T) {
	tests := []struct {
		before string
		expect hpke.KDF
	}{
		// official names
		{"hkdf_sha256", hpke.KDF_HKDF_SHA256},
		// alternate names
		{"KDF_HKDF_SHA384", hpke.KDF_HKDF_SHA384},
		// ids
		{"0x03", hpke.KDF_HKDF_SHA512},
	}

	for i, test := range tests {
		result := FindKDF(test.before)
		if result != test.expect {
			t.Errorf("test %d failed: expected '%d' but got '%d'\n", i+1, test.expect, result)
		}
	}
}

func TestFindAEAD(t *testing.T) {
	tests := []struct {
		before string
		expect hpke.AEAD
	}{
		// official names
		{"chacha20poly1305", hpke.AEAD_ChaCha20Poly1305},
		// alternate names
		{"AEAD_AES128GCM", hpke.AEAD_AES128GCM},
		// ids
		{"0x02", hpke.AEAD_AES256GCM},
	}

	for i, test := range tests {
		result := FindAEAD(test.before)
		if result != test.expect {
			t.Errorf("test %d failed: expected '%d' but got '%d'\n", i+1, test.expect, result)
		}
	}
}
