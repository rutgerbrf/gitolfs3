package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate ED25519 key: %s", err)
		os.Exit(1)
	}
	defer wipe(privateKey)

	enc := hex.NewEncoder(os.Stdout)
	print("Public  ")
	enc.Write(publicKey)
	print("\nPrivate ")
	enc.Write(privateKey.Seed())
	println()
}
