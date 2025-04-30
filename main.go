package main

import (
	"bytes"
	"io"
	"strings"
	"log"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
)

func main() {

	// double encrypt and decrypt the data, BUT make sure to read the entire data into a buffer before it is decrypted
	// for a second time
	thisIsFine()

	// double encrypt the data, then double decrypt it by running the encrypted bytes through two DecryptingReaders
	thisFails()
}

func thisIsFine() {
	testString := "hello"

	// encrypt test string once
	encryptedOnce, keysetHandle1 := encryptData(strings.NewReader(testString), "first-layer")

	// encrypt test string a second time
	encryptedTwice, keysetHandle2 := encryptData(bytes.NewReader(encryptedOnce), "second-layer")

	// decrypt the second layer of decryption
	secondLayerDecryptedReader := decryptData(bytes.NewReader(encryptedTwice), "second-layer", keysetHandle2)

	// read the entire second layer into a buffer
	secondLayerDecrypted, err := io.ReadAll(secondLayerDecryptedReader)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt the first layer of decryption
	fullyDecrypted := decryptData(bytes.NewReader(secondLayerDecrypted), "first-layer", keysetHandle1)

	all, err := io.ReadAll(fullyDecrypted)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(string(all))
}

func thisFails() {
	testString := "hello"

	// encrypt test string once
	encryptedOnce, keysetHandle1 := encryptData(strings.NewReader(testString), "first-layer")

	// encrypt test string a second time
	encryptedTwice, keysetHandle2 := encryptData(bytes.NewReader(encryptedOnce), "second-layer")

	// decrypt the second layer of decryption
	secondLayerDecrypted := decryptData(bytes.NewReader(encryptedTwice), "second-layer", keysetHandle2)

	// decrypt the first layer of decryption
	fullyDecrypted := decryptData(secondLayerDecrypted, "first-layer", keysetHandle1)

	all, err := io.ReadAll(fullyDecrypted)
	if err != nil {
		// ERROR IS THROWN HERE -> "cipher: message authentication failed"
		log.Fatal(err)
	}

	log.Print(string(all))
}

// Below here is the code I'm using to encrypt and decrypt the data

func encryptData(plaintext io.Reader, associatedData string) ([]byte, *keyset.Handle) {
	encryptedBuf := &bytes.Buffer{}

	// generate the keyset.
	ksh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if err != nil {
		log.Fatalf("failed creating keyset: %w", err)
	}

	// set up the streaming AEAD cipher
	stream, err := streamingaead.New(ksh)
	if err != nil {
		log.Fatalf("failed creating streaming aead: %w", err)
	}

	encryptedWriter, err := stream.NewEncryptingWriter(encryptedBuf, []byte(associatedData))
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(encryptedWriter, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	encryptedWriter.Close()

	return encryptedBuf.Bytes(), ksh
}

func decryptData(ciphertext io.Reader, associatedData string, ksh *keyset.Handle) io.Reader {
	// set up the streaming AEAD cipher
	stream, err := streamingaead.New(ksh)
	if err != nil {
		log.Fatalf("failed creating streaming aead: %w", err)
	}
	sr, err := stream.NewDecryptingReader(ciphertext, []byte(associatedData))
	if err != nil {
		log.Fatalf("failed creating decrypting reader: %w", err)
	}

	return sr
}
