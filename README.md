## Description

This programs aims to simulate the Uniris POW.
What is does:

- Generate X ECDSA keypairs
- Pick a random keypair
- Sign a long data
- Loop over the generated public keys
- Find the public key verifying the signature

It's using goroutines for concurrent processing.

## How to use

```go
go run main.go {NUMBER OF KEYS TO GENERATE}
```