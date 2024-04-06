package lazynacl

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/nacl/box"
)

type KeyPair struct {
	Pk *[32]byte `json:"pk"`
	Sk *[32]byte `json:"sk"`
}

func (k KeyPair) Exchange(pk *[32]byte) KeyPair {
	return KeyPair{
		Pk: pk,
		Sk: k.Sk,
	}
}

func NewKeyPair() KeyPair {
	pk, sk, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		return KeyPair{}
	}
	hex.EncodeToString(pk[:])
	hex.EncodeToString(sk[:])
	return KeyPair{
		Pk: pk,
		Sk: sk,
	}
}
