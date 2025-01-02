package lazynacl

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"
)

type KeyPair struct {
	Pk string `json:"pk"`
	Sk string `json:"sk"`
}

type PublicKeyBytes *[32]byte
type SecretKeyBytes *[32]byte

func (k KeyPair) Exchange(pk string) KeyPair {
	return KeyPair{
		Pk: pk,
		Sk: k.Sk,
	}
}

// NewKeyPair Generate a new key pair
func NewKeyPair() KeyPair {
	pk, sk, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		return KeyPair{}
	}
	return KeyPair{
		Pk: hex.EncodeToString(pk[:]),
		Sk: hex.EncodeToString(sk[:]),
	}
}

func (k KeyPair) Decode() (PublicKeyBytes, SecretKeyBytes) {
	pk, errPk := DecodeKey(k.Pk)
	if errPk != nil {
		return nil, nil
	}
	sk, errSk := DecodeKey(k.Sk)
	if errSk != nil {
		return nil, nil
	}
	return pk, sk
}

// SharedKey Perform a key exchange to derive a shared key
func (k KeyPair) SharedKey() (string, error) {
	// Convert peer public key back to *[32]byte
	peerPkBytes, err := DecodeKey(k.Pk)
	if err != nil {
		return "", fmt.Errorf("invalid peer public key: %w", err)
	}

	// Convert our secret key back to *[32]byte
	skBytes, err := DecodeKey(k.Sk)
	if err != nil {
		return "", fmt.Errorf("invalid secret key: %w", err)
	}

	// Precompute a shared key using the peer's public key and our secret key
	var sharedKey [32]byte
	box.Precompute(&sharedKey, peerPkBytes, skBytes)

	return string(sharedKey[:]), nil
}

// DecodeKey Decode a hex-encoded string into a *[32]byte
func DecodeKey(hexKey string) (*[32]byte, error) {
	bytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}
	if len(bytes) != 32 {
		return nil, fmt.Errorf("key length is not 32 bytes")
	}
	var key [32]byte
	copy(key[:], bytes)
	return &key, nil
}
