package lazynacl

import (
	cryptorand "crypto/rand"
	"io"
)

// NewNonce for random
// You must use a different nonce for each message you encrypt with the same key.
// Since the nonce here is 192 bits long, a random value provides a sufficiently small probability of repeats.
func NewNonce() [24]byte {
	var nonce [24]byte
	if _, err := io.ReadFull(cryptorand.Reader, nonce[:]); err != nil {
		return [24]byte{}
	}
	return nonce
}
