package aes256cbc

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"
)

func Benchmark_Decrypt(b *testing.B) {
	opensslEncrypted := []byte("U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=")
	passphrase := []byte("z4yH36a6zerhfE5427ZV")
	for i := 0; i < b.N; i++ {
		DecryptBase64(passphrase, opensslEncrypted)
	}
}

func TestDecryptFromString(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -a -salt
	// U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=

	opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
	passphrase := "z4yH36a6zerhfE5427ZV"

	data, err := DecryptString(passphrase, opensslEncrypted)

	if err != nil {
		t.Fatalf("Test errored: %s", err)
	}

	if string(data) != "hallowelt" {
		t.Errorf("Decryption output did not equal expected output.")
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	enc, err := EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := DecryptString(passphrase, string(enc))
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestEncryptToOpenSSL(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	enc, err := EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	// WTF? Without "echo" openssl tells us "error reading input file"
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("echo \"%s\" | openssl aes-256-cbc -k %s -d -a", string(enc), passphrase))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		t.Errorf("OpenSSL errored: %s", err)
	}

	if out.String() != plaintext {
		t.Errorf("OpenSSL output did not match input.\nOutput was: %s", out.String())
	}
}
