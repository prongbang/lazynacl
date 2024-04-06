# lazynacl

End-to-End Encryption an wrapper for Nacl in golang.

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/lazynacl)](https://goreportcard.com/report/github.com/prongbang/lazynacl)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Install

```
go get github.com/prongbang/lazynacl
```

### Benchmark

```shell
BenchmarkLazyNacl_Encrypt-10                       27480             42659 ns/op
BenchmarkLazyNacl_Decrypt-10                       28411             42298 ns/op
BenchmarkLazyNacl_EncryptPrecompute-10             28120             42594 ns/op
BenchmarkLazyNacl_DecryptPrecompute-10             28603             42268 ns/op
```

### How to use

- Create KeyPair

```go
keyPair := lazynacl.NewKeyPair()
```

- Key Exchange

```go
clientKp := lazynacl.NewKeyPair()
serverKp := lazynacl.NewKeyPair()
clientSharedKey := clientKp.Exchange(serverKp.Pk)
serverSharedKey := serverKp.Exchange(clientKp.Pk)
```

- Encrypt

```go
plaintext := `Plaintext`
ciphertext, err := lazynacl.EncryptPrecompute(plaintext, clientSharedKey)
```

- Decrypt

```go
ciphertext := "ae76477791140129a083a09ff68d5b10460f125c9affdefff48d52d30d774a7c3f42f364ea581eb9b114a65cdbf535171a"
plaintext, err := lazyEzee.DecryptPrecompute(ciphertext, serverSharedKey)
```