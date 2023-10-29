package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	protocol "cs2390-acn/pkg/protocol"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
)

type OnionRouter struct {
	AddrPort netip.AddrPort
}

type Circuit struct {
	EntryConn net.Conn
	Path      []OnionRouter
}

var CurrCircuit *Circuit

func EstablishCircuit() {
	CurrCircuit = &Circuit{}
	// TODO: change to parse directory
	CurrCircuit.Path = append(CurrCircuit.Path, OnionRouter{AddrPort: netip.MustParseAddrPort("127.0.0.1:9001")})
	// Create a socket and connect to entry OR
	conn, err := net.Dial("tcp4", CurrCircuit.Path[0].AddrPort.String())
	if err != nil {
		slog.Error("Failed to create a socket and connect to server: ", err)
	}
	CurrCircuit.EntryConn = conn
	protocol.SendCell(CurrCircuit.EntryConn, []byte("hello"))
}

func RunREPL() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Split(line, " ")
		cmd := words[0]
		switch cmd {
		case "exit":
			os.Exit(0)
		case "show-circuit":
			// TODO: print current path
		case "establish-circuit":
			EstablishCircuit()
			// TODO: create circuit
		case "send":
			// destIp := words[1]
			// message := strings.Join(words[2:], " ")
			// protocol.SendTest(ipStack, destIp, message)
		default:
			fmt.Println("Invalid command:")
			// ListCommands()
		}
	}
	fmt.Print("> ")
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	RunREPL()

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