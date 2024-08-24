package ckhpke

import (
	"strings"

	"github.com/cloudflare/circl/hpke"
)

var kemMap = map[hpke.KEM][]string{
	hpke.KEM_P256_HKDF_SHA256:        {"kem_p256_hkdf_sha256", "p256_hkdf_sha256", "0x10"},
	hpke.KEM_P384_HKDF_SHA384:        {"kem_p384_hkdf_sha384", "p384_hkdf_sha384", "0x11"},
	hpke.KEM_P521_HKDF_SHA512:        {"kem_p521_hkdf_sha512", "p521_hkdf_sha512", "0x12"},
	hpke.KEM_X25519_HKDF_SHA256:      {"kem_x25519_hkdf_sha256", "x25519_hkdf_sha256", "0x20"},
	hpke.KEM_X448_HKDF_SHA512:        {"kem_x448_hkdf_sha512", "x448_hkdf_sha512", "0x21"},
	hpke.KEM_X25519_KYBER768_DRAFT00: {"kem_x25519kyber768draft00", "x25519kyber768draft00", "kem_x25519_kyber768_draft00", "x25519_kyber768_draft00", "0x30"},
}
var kdfMap = map[hpke.KDF][]string{
	hpke.KDF_HKDF_SHA256: {"kdf_hkdf_sha256", "hkdf_sha256", "0x01"},
	hpke.KDF_HKDF_SHA384: {"kdf_hkdf_sha384", "hkdf_sha384", "0x02"},
	hpke.KDF_HKDF_SHA512: {"kdf_hkdf_sha512", "hkdf_sha512", "0x03"},
}
var aeadMap = map[hpke.AEAD][]string{
	hpke.AEAD_AES128GCM:        {"aead_aes128gcm", "aes128gcm", "0x01"},
	hpke.AEAD_AES256GCM:        {"aead_aes256gcm", "aes256gcm", "0x02"},
	hpke.AEAD_ChaCha20Poly1305: {"aead_chacha20poly1305", "chacha20poly1305", "aead_chacha20_poly1305", "chacha20_poly1305", "0x03"},
}

var kemToName = map[hpke.KEM]string{}
var kdfToName = map[hpke.KDF]string{}
var aeadToName = map[hpke.AEAD]string{}
var nameToKEM = map[string]hpke.KEM{}
var nameToKDF = map[string]hpke.KDF{}
var nameToAEAD = map[string]hpke.AEAD{}

func init() {
	for it, names := range kemMap {
		for _, name := range names {
			nameToKEM[name] = it
		}
		kemToName[it] = names[1]
	}
	for it, names := range kdfMap {
		for _, name := range names {
			nameToKDF[name] = it
		}
		kdfToName[it] = names[1]
	}
	for it, names := range aeadMap {
		for _, name := range names {
			nameToAEAD[name] = it
		}
		aeadToName[it] = names[1]
	}
}

func FindKEM(name string) hpke.KEM {
	return nameToKEM[cleanUserInput(name)]
}

func FindKDF(name string) hpke.KDF {
	return nameToKDF[cleanUserInput(name)]
}

func FindAEAD(name string) hpke.AEAD {
	return nameToAEAD[cleanUserInput(name)]
}

// cleanUserInput a name (processing steps are guesses)
func cleanUserInput(name string) string {
	name = strings.TrimSpace(name)            // 'hkdf_sha256 ' (leading/trailing spaces only)
	name = strings.ReplaceAll(name, " ", "_") // 'hkdf sha256' remaining (infix spaces)
	name = strings.ReplaceAll(name, "-", "")  // 'SHA-256' or 'aes-256-gcm'
	name = strings.ToLower(name)              // 'SHA512' or 'Aes256gcm'
	return name
}
