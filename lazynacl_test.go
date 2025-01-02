package lazynacl_test

import (
	"fmt"
	"github.com/prongbang/lazynacl"
	"testing"
)

func TestLazyNacl_Encrypt(t *testing.T) {
	// Given
	clientKeyPair := lazynacl.NewKeyPair()
	serverKeyPair := lazynacl.NewKeyPair()
	clientSharedKey := lazynacl.KeyPair{
		Pk: serverKeyPair.Pk,
		Sk: clientKeyPair.Sk,
	}
	serverSharedKey := lazynacl.KeyPair{
		Pk: clientKeyPair.Pk,
		Sk: serverKeyPair.Sk,
	}
	plaintext := ``

	// When
	actual, _ := lazynacl.Encrypt(plaintext, clientSharedKey)

	// Then
	if actual == "LazyNacl" {
		t.Errorf("Error %s", actual)
	}
	fmt.Println("pk:", serverSharedKey.Pk)
	fmt.Println("sk:", serverSharedKey.Sk)
	fmt.Println("actual:", actual)
}

func TestLazyNacl_Decrypt(t *testing.T) {
	// Given
	sharedKey := lazynacl.KeyPair{
		Pk: "ca19091aeb052c0aa5f9e4146d63f6ba28b8b3a2f19705b65a8ad48145a32e0d",
		Sk: "3bdd2f31934a97b136785c81c6ce42c9017c13b5906dd5750101373e55bf13d4",
	}
	ciphertext := "1576ed32bf03bd647f79f16e2a73c8f7f1c43c4445c578d53a3294e2def609a072093618d23b67b8"

	// When
	actual, err := lazynacl.Decrypt(ciphertext, sharedKey)

	// Then
	if actual != "LazyNacl" && err != nil {
		t.Errorf("Error %s, %s", actual, err.Error())
	}
}

func TestLazyNacl_EncryptPrecompute(t *testing.T) {
	// Given
	clientKeyPair := lazynacl.NewKeyPair()
	serverKeyPair := lazynacl.NewKeyPair()
	clientSharedKey := lazynacl.KeyPair{
		Pk: serverKeyPair.Pk,
		Sk: clientKeyPair.Sk,
	}
	serverSharedKey := lazynacl.KeyPair{
		Pk: clientKeyPair.Pk,
		Sk: serverKeyPair.Sk,
	}
	plaintext := `LazyNacl`

	// When
	actual, _ := lazynacl.EncryptPrecompute(plaintext, clientSharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
	fmt.Println("pk:", serverSharedKey.Pk)
	fmt.Println("sk:", serverSharedKey.Sk)
	fmt.Println("actual:", actual)
}

func TestLazyNacl_DecryptPrecompute(t *testing.T) {
	// Given
	sharedKey := lazynacl.KeyPair{
		Pk: "490caade7760b6fa8a8a97b39d38a8cde82fa490a3747bfc9d50453c1cba8d3d",
		Sk: "77d995fe6b9c12cb2299cd17eb4b20007167f54e9235ec3a398fce795833aa2f",
	}
	ciphertext := "44682cb96da9ae354fff2383bdc31bc996de29a5db2aa940d96ef78d76f9fd563b817e78e811b7b9fb67bfb1ab6926e6"

	// When
	actual, _ := lazynacl.Decrypt(ciphertext, sharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
}

func BenchmarkLazyNacl_Encrypt(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: "6a7d4551e0bfbd86c84f4a7506cd59889ca4871cd285578f3fba52eceecd7864",
		Sk: "454178a50f8a25fb2df501c1a3fe616b93614825aa0acddba4880d7b9984c3aa",
	}
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_, err := lazynacl.Encrypt(plaintext, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err.Error())
		}
	}
}

func BenchmarkLazyNacl_Decrypt(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: "6a7d4551e0bfbd86c84f4a7506cd59889ca4871cd285578f3fba52eceecd7864",
		Sk: "454178a50f8a25fb2df501c1a3fe616b93614825aa0acddba4880d7b9984c3aa",
	}
	ciphertext := `03711f898948f1a35b46cb238e512bf8c3e31bd65834c55f7e8cc10affaf9b49de9c45f89bbe8504fe9c66beaf25d3c0`

	for i := 0; i < b.N; i++ {
		_, err := lazynacl.Decrypt(ciphertext, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err.Error())
		}
	}
}

func BenchmarkLazyNacl_EncryptPrecompute(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: "6a7d4551e0bfbd86c84f4a7506cd59889ca4871cd285578f3fba52eceecd7864",
		Sk: "454178a50f8a25fb2df501c1a3fe616b93614825aa0acddba4880d7b9984c3aa",
	}
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_, err := lazynacl.EncryptPrecompute(plaintext, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err.Error())
		}
	}
}

func BenchmarkLazyNacl_DecryptPrecompute(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: "6a7d4551e0bfbd86c84f4a7506cd59889ca4871cd285578f3fba52eceecd7864",
		Sk: "454178a50f8a25fb2df501c1a3fe616b93614825aa0acddba4880d7b9984c3aa",
	}
	ciphertext := `03711f898948f1a35b46cb238e512bf8c3e31bd65834c55f7e8cc10affaf9b49de9c45f89bbe8504fe9c66beaf25d3c0`

	for i := 0; i < b.N; i++ {
		_, err := lazynacl.DecryptPrecompute(ciphertext, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err.Error())
		}
	}
}
