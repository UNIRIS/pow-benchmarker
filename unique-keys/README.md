## Description

This programs aims to simulate the POW for Uniris if we unique keys between the biometric device.
What is does:

- Generate X ECDSA keypairs
- Pick a random keypair
- Sign a long data
- Loop over the stored keypairs
- Find the key which will verify the signature

It's using goroutines for concurrent processing.

## How to use

```go
go run main.go {NUMBER OF KEYS TO GENERATE}
```