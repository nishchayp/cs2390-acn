package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	crypto "cs2390-acn/pkg/crypto"
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

	/* Workflow:
	1. Generating a Diffie-Hellman key pair.
	2. Computing a shared secret using the public key from the key pair (simulating a handshake with another party).
	3. Hashing the shared secret to fit the size required for AES.
	4. Test AES: Using the hashed shared secret as a key to encrypt and decrypt data.
	*/

	// Step 1: Generate ECDH key pair for Diffie-Hellman handshake, using Alice & Bob as an example
	curve := ecdh.P256()
	privKey1, pubKey1, err := crypto.GenerateKeyPair(curve)
	if err != nil {
		slog.Error("Error generating ECDH key pair for Alice:", err)
		return
	}

	privKey2, pubKey2, err := crypto.GenerateKeyPair(curve)
	if err != nil {
		slog.Error("Failed to generate ECDH key pair for Bob:", err)
		return
	}
	// Step 2: Computing a shared secret
	secret1, err := crypto.ComputeSharedSecret(privKey1, pubKey2)
	if err != nil {
		slog.Error("Failed to compute shared secret for Alice:", err)
		return
	}

	secret2, err := crypto.ComputeSharedSecret(privKey2, pubKey1)
	if err != nil {
		slog.Error("Failed to compute shared secret for Bob:", err)
		return
	}

	if bytes.Equal(secret1, secret2) {
		slog.Info("Diffie-Hellman key exchange successful!")
	} else {
		slog.Error("Diffie-Hellman key exchange failed!")
	}
	// CONSIDER: why hash and not just use shaed secret
	// Step 3: Hashing
	hashedSecret := crypto.Hash(secret1)
	hashedSecret2 := crypto.Hash(secret2)
	if bytes.Equal(hashedSecret, hashedSecret2) {
		slog.Info("Hashing is deterministic!")
	} else {
		slog.Error("Hashing is not deterministic!")
	}

	// Step 4: Test AES functions
	// Use the hashed secret as a key to encrypt and decrypt data
	data := []byte("This is a test message.")
	encryptedData, err := crypto.EncryptData(data, hashedSecret)
	if err != nil {
		slog.Error("Error encrypting data:", err)
		return
	}

	slog.Info("Encrypted Data:", hex.EncodeToString(encryptedData))

	decryptedData, err := crypto.DecryptData(encryptedData, hashedSecret)
	if err != nil {
		slog.Error("Error decrypting data:", err)
		return
	}

	if string(decryptedData) == string(data) {
		slog.Info("Decryption successful! Decrypted message:", string(decryptedData))
	} else {
		slog.Error("Decryption failed. Decrypted data does not match original.")
	}
}
