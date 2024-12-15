package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

func generatePublic(privateKey string) string {
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return ""
	}
	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return ""
	}
	pubKeyBytes := crypto.CompressPubkey(&privKey.PublicKey)
	return hex.EncodeToString(pubKeyBytes)
}

func generateBitcoinAddress(publicKey string) string {
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	shaHash := sha256.Sum256(pubKeyBytes)
	ripemdHash := ripemd160.New()
	ripemdHash.Write(shaHash[:])
	address := append([]byte{0x00}, ripemdHash.Sum(nil)...)
	checksum := sha256.Sum256(address)
	checksum = sha256.Sum256(checksum[:])
	return base58.Encode(append(address, checksum[:4]...))
}

func generateWIF(privateKey string) string {
	privKeyBytes, _ := hex.DecodeString(privateKey)
	prefix := append([]byte{0x80}, privKeyBytes...)
	hash1 := sha256.Sum256(prefix)
	hash2 := sha256.Sum256(hash1[:])
	return base58.Encode(append(prefix, hash2[:4]...))
}

func createRandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	rangeStr := "0123456789abcdef"
	result := make([]byte, length)
	for i := range result {
		result[i] = rangeStr[rand.Intn(len(rangeStr))]
	}
	return string(result)
}

func replaceXtoRandomNumber(privateKey, randRange string) string {
	var sb strings.Builder
	index := 0
	for _, char := range privateKey {
		if char == 'x' {
			sb.WriteByte(randRange[index])
			index++
		} else {
			sb.WriteByte(byte(char))
		}
	}
	return sb.String()
}

func worker(wallet, privatKey string, result chan string, count *int64) {
	for {
		countX := strings.Count(privatKey, "x")
		randRange := createRandomString(countX)
		newPrivateKey := replaceXtoRandomNumber(privatKey, randRange)
		publicKey := generatePublic(newPrivateKey)
		address := generateBitcoinAddress(publicKey)

		atomic.AddInt64(count, 1)

		if wallet == address {
			result <- newPrivateKey
			return
		}
	}
}

func main() {
	wallet := "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC"
	privatKey := "403b3d4fcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x"

	var count int64
	startTime := time.Now()
	numWorkers := 12
	result := make(chan string)

	for i := 0; i < numWorkers; i++ {
		go worker(wallet, privatKey, result, &count)
	}

	go func() {
		for {
			elapsedTime := time.Since(startTime).Seconds()
			keysPerSecond := float64(atomic.LoadInt64(&count)) / elapsedTime
			fmt.Printf("\rChaves verificadas: %d | Chaves/s: %.2f", atomic.LoadInt64(&count), keysPerSecond)
			time.Sleep(1 * time.Second)
		}
	}()

	foundPrivateKey := <-result
	elapsedTime := time.Since(startTime)

	fmt.Println("\nAchei a chave privada!")
	fmt.Println("Tempo decorrido:", elapsedTime)
	fmt.Println("Chave Privada:", foundPrivateKey)
	fmt.Println("Chave Pública:", generatePublic(foundPrivateKey))
	fmt.Println("Endereço Bitcoin:", wallet)
	fmt.Println("WIF:", generateWIF(foundPrivateKey))
}
