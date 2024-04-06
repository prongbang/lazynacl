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
	clientSharedKey := clientKeyPair.Exchange(serverKeyPair.Pk)
	serverSharedKey := serverKeyPair.Exchange(clientKeyPair.Pk)
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	// When
	actual := lazynacl.Encrypt(plaintext, clientSharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
	fmt.Println("pk:", serverSharedKey.Pk)
	fmt.Println("sk:", serverSharedKey.Sk)
	fmt.Println("actual:", actual)
}

func TestLazyNacl_Decrypt(t *testing.T) {
	// Given
	sharedKey := lazynacl.KeyPair{
		Pk: &[32]byte{239, 227, 174, 134, 229, 168, 151, 117, 63, 57, 219, 151, 114, 132, 155, 234, 30, 127, 64, 241, 129, 67, 129, 114, 217, 138, 255, 231, 18, 13, 128, 46},
		Sk: &[32]byte{141, 127, 93, 198, 93, 42, 185, 86, 200, 253, 91, 157, 6, 4, 176, 4, 235, 170, 94, 44, 217, 14, 23, 172, 217, 243, 49, 126, 64, 61, 193, 165},
	}
	ciphertext := "51bc5775dda2401fe7611437af1b3ebb4480c7e94974c135638e0a0ecdb7663cde8f130658d935206ec223fa"

	// When
	actual := lazynacl.Decrypt(ciphertext, sharedKey)

	// Then
	if actual != "Nacl" {
		t.Errorf("Error %s", actual)
	}
}

func TestLazyNacl_EncryptPrecompute(t *testing.T) {
	// Given
	clientKeyPair := lazynacl.NewKeyPair()
	serverKeyPair := lazynacl.NewKeyPair()
	clientSharedKey := clientKeyPair.Exchange(serverKeyPair.Pk)
	serverSharedKey := serverKeyPair.Exchange(clientKeyPair.Pk)
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	// When
	actual := lazynacl.EncryptPrecompute(plaintext, clientSharedKey)

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
		Pk: &[32]byte{146, 186, 24, 147, 144, 61, 132, 151, 128, 29, 210, 23, 180, 94, 201, 146, 117, 94, 67, 105, 197, 10, 252, 37, 233, 124, 118, 85, 204, 89, 12, 100},
		Sk: &[32]byte{124, 3, 53, 50, 1, 208, 148, 47, 220, 102, 24, 29, 252, 189, 12, 116, 48, 247, 61, 71, 13, 217, 124, 150, 133, 203, 144, 3, 84, 237, 115, 0},
	}
	ciphertext := "f2da85e282bb6e2104f08ebbba9295e2ed854f7edc1ee09079a6ea83a44600e43696b9117ff3e1fac09a9b5339536412a9d045e374cb23afc3f5a2fd7ce7dc91310a391e9b8d63f6aa9da96c99d81471fb315f6184bf18e0794e4cc72f1ce8a0e2846b2bd4122e473f9bd0cec845f51c4fc20d138265d01da4f8a7af0d6029c855ac3d1844e33262f5998b0b785035ceb62d7db70b"

	// When
	actual := lazynacl.Decrypt(ciphertext, sharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
}

func BenchmarkLazyNacl_Encrypt(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: &[32]byte{239, 227, 174, 134, 229, 168, 151, 117, 63, 57, 219, 151, 114, 132, 155, 234, 30, 127, 64, 241, 129, 67, 129, 114, 217, 138, 255, 231, 18, 13, 128, 46},
		Sk: &[32]byte{141, 127, 93, 198, 93, 42, 185, 86, 200, 253, 91, 157, 6, 4, 176, 4, 235, 170, 94, 44, 217, 14, 23, 172, 217, 243, 49, 126, 64, 61, 193, 165},
	}
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_ = lazynacl.Encrypt(plaintext, sharedKey)
	}
}

func BenchmarkLazyNacl_Decrypt(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: &[32]byte{246, 70, 7, 165, 4, 170, 72, 224, 49, 176, 0, 186, 168, 85, 214, 195, 170, 166, 128, 177, 234, 106, 75, 206, 254, 198, 118, 79, 95, 251, 31, 59},
		Sk: &[32]byte{105, 179, 88, 5, 36, 159, 38, 46, 103, 248, 156, 152, 138, 197, 28, 131, 118, 18, 113, 155, 104, 24, 212, 182, 239, 94, 203, 203, 84, 133, 204, 252},
	}
	ciphertext := `0ead75a4e9a3833ce6429d2f57164542c63a51a1fcac122dd67cfafdacc3e61a7d23cda2fbf8cc2d62e775872f9cd4a68a755e97e39b4b9b459ad32a73834c6fcc62b059d9436411dc90fb133df6bd3290dc663969f65ec315783c9bbdffbd0d60830d407e3703ef7b9aab006c4a49c6c90b517cb59705508ab2c6aad885b11824f975c1c41d5183f2426c7329f2168f3bfb1fd734`

	for i := 0; i < b.N; i++ {
		_ = lazynacl.Decrypt(ciphertext, sharedKey)
	}
}

func BenchmarkLazyNacl_EncryptPrecompute(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: &[32]byte{246, 70, 7, 165, 4, 170, 72, 224, 49, 176, 0, 186, 168, 85, 214, 195, 170, 166, 128, 177, 234, 106, 75, 206, 254, 198, 118, 79, 95, 251, 31, 59},
		Sk: &[32]byte{105, 179, 88, 5, 36, 159, 38, 46, 103, 248, 156, 152, 138, 197, 28, 131, 118, 18, 113, 155, 104, 24, 212, 182, 239, 94, 203, 203, 84, 133, 204, 252},
	}
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_ = lazynacl.EncryptPrecompute(plaintext, sharedKey)
	}
}

func BenchmarkLazyNacl_DecryptPrecompute(b *testing.B) {
	sharedKey := lazynacl.KeyPair{
		Pk: &[32]byte{246, 70, 7, 165, 4, 170, 72, 224, 49, 176, 0, 186, 168, 85, 214, 195, 170, 166, 128, 177, 234, 106, 75, 206, 254, 198, 118, 79, 95, 251, 31, 59},
		Sk: &[32]byte{105, 179, 88, 5, 36, 159, 38, 46, 103, 248, 156, 152, 138, 197, 28, 131, 118, 18, 113, 155, 104, 24, 212, 182, 239, 94, 203, 203, 84, 133, 204, 252},
	}
	ciphertext := `f2da85e282bb6e2104f08ebbba9295e2ed854f7edc1ee09079a6ea83a44600e43696b9117ff3e1fac09a9b5339536412a9d045e374cb23afc3f5a2fd7ce7dc91310a391e9b8d63f6aa9da96c99d81471fb315f6184bf18e0794e4cc72f1ce8a0e2846b2bd4122e473f9bd0cec845f51c4fc20d138265d01da4f8a7af0d6029c855ac3d1844e33262f5998b0b785035ceb62d7db70b`

	for i := 0; i < b.N; i++ {
		_ = lazynacl.DecryptPrecompute(ciphertext, sharedKey)
	}
}
