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

## Outputs 

The program produces 4 outputs:
- The elasped time to generate X keypairs
- The index of the random key to sign the data
- The elapsed time to find the right public key (PoW)
- The elapsed time to loop over all the keys