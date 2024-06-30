package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/argon2"

	"github.com/zytekaron/zpke/ckhpke"
)

var modeGenerate, modeEncrypt, modeDecrypt bool
var kemName, kdfName, aeadName, keyFileName, keyPassword, inputFileName, outputFileName string

var selKEM hpke.KEM
var selKDF hpke.KDF
var selAEAD hpke.AEAD
var suite hpke.Suite

const usageText = `usage:
generate keys:
  hpke-cli -g -k zytekaron
encrypt:
  hpke-cli -e -k zytekaron_pub.key -i message.txt -o encrypted.bin
decrypt:
  hpke-cli -d -k zytekaron_priv.key -i encrypted.bin -o decrypted.txt
`

func init() {
	return // run tests

	pflag.BoolVarP(&modeGenerate, "generate", "g", false, "generate mode")
	pflag.BoolVarP(&modeEncrypt, "encrypt", "e", false, "encryption mode")
	pflag.BoolVarP(&modeDecrypt, "decrypt", "d", false, "decryption mode")

	pflag.StringVarP(&keyFileName, "key", "k", "", "key file name")
	pflag.StringVarP(&keyPassword, "password", "p", "", "key password")

	pflag.StringVarP(&inputFileName, "input", "i", "", "input file name")
	pflag.StringVarP(&outputFileName, "output", "o", "", "output file name")

	pflag.StringVarP(&kemName, "kem", "K", "x25519kyber768draft00", "(k)ey encapsulation mechanism")
	pflag.StringVarP(&kdfName, "kdf", "D", "hkdf_sha256", "key (d)erivation function")
	pflag.StringVarP(&aeadName, "aead", "A", "aes256gcm", "(a)symmetric encryption with associated data")

	pflag.Parse()

	selKEM = ckhpke.FindKEM(kemName)
	if selKEM == 0 {
		fmt.Println("invalid kem")
		os.Exit(0)
	}
	selKDF = ckhpke.FindKDF(kdfName)
	if selKDF == 0 {
		fmt.Println("invalid kdf")
		os.Exit(0)
	}
	selAEAD = ckhpke.FindAEAD(aeadName)
	if selAEAD == 0 {
		fmt.Println("invalid aead")
		os.Exit(0)
	}

	suite = hpke.NewSuite(selKEM, selKDF, selAEAD)

	count := countBool(modeEncrypt, modeDecrypt)
	if count == 0 {
		pflag.PrintDefaults()
		os.Exit(0)
	} else if count > 1 {
		fmt.Println("select only one mode (encrypt, decrypt)")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	// example notes for user:
	// - kem, kdf, aead - all are ignored during decryption
	//   (validate the key.KEM() against the msg.KEM(), but do no more)
}

func main() {
	testDeterministicKeyPair()
	testSaveLoadKeys()

	return // run tests

	pk, sk, err := ckhpke.GenerateKeyPair(selKEM, "", "")
	if selKEM == 0 {
		log.Fatalln("failed to gen keypair:", err)
	}

	in1 := try(os.Open("td/radxa-zero3_debian_bullseye_xfce_b6.img"))
	out1 := try(os.Create("td/encrypted.out"))
	start := time.Now()
	err = ckhpke.TestEncryptSave(out1, in1, suite, pk)
	if err != nil {
		log.Fatalln("test-encrypt-save:", err)
	}
	fmt.Println("ENC elapsed ms", time.Since(start).Milliseconds())
	out1.Close()
	in1.Close()

	in2 := try(os.Open("td/encrypted.out"))
	out2 := try(os.Create("td/decrypted.dat"))
	start = time.Now()
	err = ckhpke.TestLoadDecrypt(out2, in2, sk)
	if err != nil {
		log.Fatalln("test-load-decrypt:", err)
	}
	fmt.Println("DEC elapsed ms", time.Since(start).Milliseconds())
	out2.Close()
	in2.Close()

	//switch {
	//case modeGenerate:
	//case modeEncrypt:
	//case modeDecrypt:
	//}
}

func try[T any](t T, err error) T {
	if err != nil {
		panic("try: " + err.Error())
	}
	return t
}

func try2[T, U any](t T, u U, err error) (T, U) {
	if err != nil {
		panic("try: " + err.Error())
	}
	return t, u
}

func testDeterministicKeyPair() {
	const password = "Password123"

	kem := hpke.KEM_P521_HKDF_SHA512
	scheme := kem.Scheme()

	start := time.Now()
	seed := argon2.IDKey([]byte(password), nil, 4, 256*1024, 4, uint32(scheme.SeedSize()))
	elapsed := time.Since(start)
	fmt.Printf("(argon2: %d ms)\n\n", elapsed.Milliseconds())

	apk, ask, err := ckhpke.GenerateKeyPairFromSeed(kem, seed, "A", "Key A")
	if err != nil {
		log.Fatalln("generate 1:", err)
	}

	bpk, bsk, err := ckhpke.GenerateKeyPairFromSeed(kem, seed, "B", "Key B")
	if err != nil {
		log.Fatalln("generate 2:", err)
	}

	fmt.Println("same?", apk.Signature() == bpk.Signature() && ask.Signature() == bsk.Signature())
}

func testSaveLoadKeys() {
	const name = "Michael Thornes"
	const comment = "Zytekaron"

	selKEM = hpke.KEM_X25519_HKDF_SHA256

	key := []byte("Hello, World!!")

	pk, sk, err := ckhpke.GenerateKeyPair(selKEM, name, comment)
	if selKEM == 0 {
		log.Fatalln("failed to gen keypair:", err)
	}

	fmt.Println("Public:", pk)
	fmt.Println("Private:", sk)
	fmt.Println(pk.Signature(), sk.Signature())

	err = ckhpke.SavePublicKey("testdir/pub.pem", pk)
	if err != nil {
		log.Fatalln("failed to save sk:", err)
	}
	err = ckhpke.SavePrivateKey("testdir/priv.pem", sk, nil)
	if err != nil {
		log.Fatalln("failed to save sk:", err)
	}
	err = ckhpke.SavePrivateKey("testdir/priv_encrypted.pem", sk, key)
	if err != nil {
		log.Fatalln("failed to save encrypted sk:", err)
	}

	pk, err = ckhpke.LoadPublicKey("testdir/pub.pem")
	if err != nil {
		log.Fatalln("failed to load sk:", err)
	}
	sk, err = ckhpke.LoadPrivateKey("testdir/priv.pem", nil)
	if err != nil {
		log.Fatalln("failed to load sk:", err)
	}
	fmt.Println()
	fmt.Println("Public:", pk)
	fmt.Println("Private:", sk)
	fmt.Println(pk.Signature(), sk.Signature())

	sk, err = ckhpke.LoadPrivateKey("testdir/priv_encrypted.pem", key)
	if err != nil {
		log.Fatalln("failed to load encrypted sk:", err)
	}
	fmt.Println()
	fmt.Println("Public:", pk)
	fmt.Println("Private:", sk)
	fmt.Println(pk.Signature(), sk.Signature())
}

func countBool(bools ...bool) int {
	count := 0
	for _, b := range bools {
		if b {
			count++
		}
	}
	return count
}
