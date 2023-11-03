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

func SendRelayExtendCell(nextHopPublicKey *ecdh.PublicKey) error {
	// Construct the payload with OP public key (RSA encrypted) and next hop's IP (plain)
	// For RSA encryption, use the provided public key of the next hop
	// Since we're skipping the RSA encryption part, I'm directly marshalling the public key
	_, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
	// sessionPrivKey unused for now (not received any response yet)
	if err != nil {
		slog.Error("Failed to generate session key pair", "Err", err)
		return err
	}
	nextORHop := self.CurrCircuit.Path[1]

	// 　Marshall Address
	relayExtendCellPayload := protocol.RelayExtendCellPayload{
		PublicKey:  sessionPubKey, // RSA_Enc(sessionPubKey, OR2's public key)
		NextORAddr: nextORHop.AddrPort,
	}

	marshalledExtendPayload, _ := relayExtendCellPayload.Marshall()

	// marshalledORHop, err := models.MarshallORHop(nextORHop)
	// if err != nil {
	// 	slog.Error("Failed to marshal nextORHop", "Err", err)
	// 	return err
	// }

	// marshalledPubKey, err := x509.MarshalPKIXPublicKey(sessionPubKey)
	// if err != nil {
	// 	slog.Error("Failed to marshal public key", "Err", err)
	// 	return err
	// }

	// // Data = ORHop + PubKey
	// dataPayload := append(marshalledPubKey, marshalledORHop...)

	// // Truncate or pad the payload as necessary to fit the relay cell size
	// if len(dataPayload) < protocol.RelayPayloadSize {
	// 	dataPayload = append(dataPayload, make([]byte, protocol.RelayPayloadSize-len(dataPayload))...)
	// } else {
	// 	dataPayload = dataPayload[:protocol.RelayPayloadSize]
	// }

	digest := crypto.HashDigest(marshalledExtendPayload)

	// Construct the relay cell payload
	relayPayload := protocol.RelayCellPayload{
		StreamID: 0, // TODO: Set the StreamID if needed in the future
		Digest:   [protocol.DigestSize]byte(digest),
		Len:      uint16(len(marshalledExtendPayload)),
		Cmd:      protocol.Extend,
	}
	copy(relayPayload.Data[:], marshalledExtendPayload)
	// Encrypt the payload using the shared symmetric key with the Entry OR
	sharedSecret := self.CurrCircuit.Path[0].SharedSymKey
	marshalledPayload, err := relayPayload.Marshall()
	if err != nil {
		slog.Error("Failed to marshall relay payload", "Err", err)
		return err
	}
	encryptedRelayPayload, err := crypto.EncryptData(sharedSecret, marshalledPayload[:])
	if err != nil {
		slog.Error("Failed to encrypt marshalled relay payload", "Err", err)
		return err
	}

	// Create a relay cell and send it
	relayCell := protocol.Cell{
		CircID: self.CurrCircuit.Path[0].CircID, // Use the circuit ID for the entry node
		Cmd:    uint8(protocol.Relay),
	}
	copy(relayCell.Data[:], encryptedRelayPayload)

	relayCell.Send(self.CurrCircuit.EntryConn)

	respRelayCell := protocol.Cell{}
	respRelayCell.Recv(self.CurrCircuit.EntryConn)
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

	// RunREPL()

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
	slog.Debug("Alice AES Private Key ", hex.EncodeToString(privKey1.Bytes()))
	slog.Debug("Alice AES Public Key ", hex.EncodeToString(pubKey1.Bytes()))

	privKey2, pubKey2, err := crypto.GenerateKeyPair(curve)
	// Generate RSA key pair for Bob
	privRSAKey2, pubRSAKey2, err := crypto.GenerateRSAKeys()

	// Encrypt and Decrypt Alice's AES public key using RSA key pair.
	cipherKey1, err := crypto.EncryptWithPublicKey(pubKey1.Bytes(), pubRSAKey2)
	slog.Debug("Alice RSA Encrypted her Public Key to Bob: ", hex.EncodeToString(cipherKey1))

	decryptMsgKey1, err := crypto.DecryptWithPrivateKey(cipherKey1, privRSAKey2)

	slog.Debug("Bob RSA Decrypted Public Key from Alice: ", hex.EncodeToString(decryptMsgKey1))

	if bytes.Equal(pubKey1.Bytes(), decryptMsgKey1) {
		slog.Info("************** RSA succeeded ***************")
	} else {
		slog.Error("************** RSA encryption failed **************")
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
		slog.Info("************** Diffie-Hellman key exchange succeeded!************** ")
	} else {
		slog.Error("************** Diffie-Hellman key exchange failed!************** ")
	}
	// CONSIDER: why hash and not just use shaed secret
	// Step 3: Hashing
	hashedSecret := crypto.Hash(secret1)
	hashedSecret2 := crypto.Hash(secret2)
	if bytes.Equal(hashedSecret, hashedSecret2) {
		slog.Info("************** Hashing is deterministic! **************")
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
		slog.Info("************** Decryption successful!************** \n Decrypted message:", string(decryptedData))
	} else {
		slog.Error("Decryption failed. Decrypted data does not match original.")
	}
}
