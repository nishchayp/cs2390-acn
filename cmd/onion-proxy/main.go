package main

import (
	"bytes"
	"crypto/ecdh"
	protocol "cs2390-acn/pkg/protocol"
	"encoding/hex"
	"log/slog"
	"os"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	slog.SetDefault(logger)

	slog.Info("hi")

	/* TEST crypto.go */
	// Test AES functions
	originalData := []byte("This is some test data for AES encryption!")

	aesKey, err := protocol.GenerateAESKey()
	if err != nil {
		slog.Error("Failed to generate AES key:", err)
		return
	}

	encryptedData, err := protocol.EncryptData(originalData, aesKey)
	if err != nil {
		slog.Error("Failed to encrypt data:", err)
		return
	}

	decryptedData, err := protocol.DecryptData(encryptedData, aesKey)
	if err != nil {
		slog.Error("Failed to decrypt data:", err)
		return
	}

	if bytes.Equal(originalData, decryptedData) {
		slog.Info("AES encryption and decryption successful!")
	} else {
		slog.Error("AES encryption and decryption failed!")
	}

	// Test Diffie-Hellman functions
	curve := ecdh.P256() // Using P256 curve as an example
	privKey1, pubKey1, err := protocol.GenerateKeyPair(curve)
	if err != nil {
		slog.Error("Failed to generate ECDH key pair for Alice:", err)
		return
	}

	privKey2, pubKey2, err := protocol.GenerateKeyPair(curve)
	if err != nil {
		slog.Error("Failed to generate ECDH key pair for Bob:", err)
		return
	}

	secret1, err := protocol.ComputeSharedSecret(privKey1, pubKey2)
	if err != nil {
		slog.Error("Failed to compute shared secret for Alice:", err)
		return
	}

	secret2, err := protocol.ComputeSharedSecret(privKey2, pubKey1)
	if err != nil {
		slog.Error("Failed to compute shared secret for Bob:", err)
		return
	}

	if bytes.Equal(secret1, secret2) {
		slog.Info("Diffie-Hellman key exchange successful!")
	} else {
		slog.Error("Diffie-Hellman key exchange failed!")
	}

	// Mock shared secret for testing
	secret := []byte("This is a test shared secret")

	// Hash the mock secret using the hashSharedSecret function from the protocol package
	hashedSecret := protocol.HashSharedSecret(secret)

	// Display the hashed secret using slog
	slog.Info("Original Secret: ", string(secret))
	slog.Info("Hashed Secret: ", hex.EncodeToString(hashedSecret))
}