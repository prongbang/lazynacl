package lazynacl

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"io"
)

func Encrypt(plaintext string, keyPair KeyPair) (string, error) {
	cipherByte, err := EncryptBytes([]byte(plaintext), keyPair)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherByte), nil
}

func EncryptBytes(plaintext []byte, keyPair KeyPair) ([]byte, error) {
	nonce := NewNonce()
	pk, sk := keyPair.Decode()
	return box.Seal(nonce[:], plaintext, &nonce, pk, sk), nil
}

func Decrypt(ciphertext string, keyPair KeyPair) (string, error) {
	encrypted, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decrypted, err := DecryptBytes(encrypted, keyPair)
	return string(decrypted), err
}

func DecryptBytes(ciphertext []byte, keyPair KeyPair) ([]byte, error) {
	// The recipient can decrypt the message using their private key and the sender's public key.
	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])

	pk, sk := keyPair.Decode()
	decrypted, ok := box.Open(nil, ciphertext[24:], &decryptNonce, pk, sk)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decrypted, nil
}

func EncryptPrecompute(plaintext string, keyPair KeyPair) (string, error) {
	encrypted, err := EncryptPrecomputeBytes([]byte(plaintext), keyPair)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

func EncryptPrecomputeBytes(plaintext []byte, keyPair KeyPair) ([]byte, error) {
	// The shared key can be used to speed up processing when using the same pair of keys repeatedly.
	sharedEncryptKey := new([32]byte)
	pk, sk := keyPair.Decode()
	box.Precompute(sharedEncryptKey, pk, sk)

	// You must use a different nonce for each message you encrypt with the same key.
	var nonce [24]byte
	if _, err := io.ReadFull(cryptorand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// This encrypts msg and appends the result to the nonce.
	encrypted := box.SealAfterPrecomputation(nonce[:], plaintext, &nonce, sharedEncryptKey)
	return encrypted, nil
}

func DecryptPrecompute(ciphertext string, keyPair KeyPair) (string, error) {
	encrypted, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decrypted, err := DecryptPrecomputeBytes(encrypted, keyPair)
	return string(decrypted), err
}

func DecryptPrecomputeBytes(ciphertext []byte, keyPair KeyPair) ([]byte, error) {
	// The shared key can be used to speed up processing when using the same pair of keys repeatedly.
	var sharedDecryptKey [32]byte
	pk, sk := keyPair.Decode()
	box.Precompute(&sharedDecryptKey, pk, sk)

	// The recipient can decrypt the message using the shared key.
	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, ciphertext[24:], &decryptNonce, &sharedDecryptKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return decrypted, nil
}
