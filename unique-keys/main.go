package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"
)

type keyPair struct {
	Private string
	Public  string
}

func main() {

	args := os.Args
	nbKeys, _ := strconv.Atoi(args[1])
	keyChan := make(chan keyPair, nbKeys)

	startInit := time.Now()

	//Generate keys
	for i := 0; i < nbKeys; i++ {
		go func() {
			keyChan <- generateKey()
		}()
	}

	var wg sync.WaitGroup
	wg.Add(nbKeys)

	//Store the keys
	keyPairs := make([]keyPair, 0)

	go func() {
		for kp := range keyChan {
			keyPairs = append(keyPairs, kp)
			wg.Done()
		}
	}()

	wg.Wait()

	elapsedInit := time.Since(startInit)
	log.Printf("%f seconds to generate %d keys\n", elapsedInit.Seconds(), nbKeys)

	rand.Seed(time.Now().UnixNano())
	rnd := rand.Intn(len(keyPairs))
	randomKeyPair := keyPairs[rnd]

	data := "ed399d7e3aada3beef16c23aec0c6746c607e351a820bddde7d9e5541f03b0b3c602dcf8a4c7399b406ec9751f8339e847dd4270e8047e786cd75630f2cc2f4b4e7eeae04376cabe85cb7bf387bbff9f85abf2b47221a4662d66cc463b5f53344d1395b2140ed5a913f3feaf4ef057987caa36814ae4b1a2d76665e2c16d380f1abf366c507670ada37e962358f162c5a5efec2cfb75a446107ce59ceccc8d62acab6c3c672e9afdfd02b743036ec66ba23ed1cd2559a23cb9bf42a6d1d7248b0633c48d8969cc31e495c74d8b72afa4ca29d392c0b077035b34e6efb8f9319365c4ccce5a593fab11ab2ca79e38947dbeb884f9f83a2698a0a07aef70eece"

	pvDecoded, _ := hex.DecodeString(randomKeyPair.Private)
	pvKey, _ := x509.ParseECPrivateKey(pvDecoded)
	r, s, _ := ecdsa.Sign(crand.Reader, pvKey, []byte(data))
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})

	startPow := time.Now()
	founded := make(chan bool, 1)

	for _, kp := range keyPairs {
		go func(key string) {
			if checkSignature(key, data, hex.EncodeToString(sig)) {
				founded <- true
			}
		}(kp.Public)
	}

	<-founded
	elapsedPow := time.Since(startPow)
	log.Printf("%f seconds to find the signature", elapsedPow.Seconds())
}

func generateKey() keyPair {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	return keyPair{
		Private: hex.EncodeToString(pvKey),
		Public:  hex.EncodeToString(pubKey),
	}
}

func checkSignature(key string, data string, der string) bool {
	decodedkey, _ := hex.DecodeString(key)
	pubKey, _ := x509.ParsePKIXPublicKey(decodedkey)
	ecdsaPublic := pubKey.(*ecdsa.PublicKey)

	decodedsig, _ := hex.DecodeString(der)
	var sig struct {
		R, S *big.Int
	}
	asn1.Unmarshal(decodedsig, &sig)

	return ecdsa.Verify(ecdsaPublic, []byte(data), sig.R, sig.S)
}
