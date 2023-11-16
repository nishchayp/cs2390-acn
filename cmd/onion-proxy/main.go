package main

import (
	"bufio"
	"crypto/ecdh"
	"cs2390-acn/pkg/common"
	"cs2390-acn/pkg/crypto"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
)

// Global declaration
var self *models.OnionProxy

// Initialize the instance of Onion Router
func InitializeSelf() (*models.OnionProxy, error) {
	op := &models.OnionProxy{
		CircIDCounter: 0,
		CircuitMap:    make(map[uint16]models.Circuit),
		Curve:         ecdh.P256(),
	}
	return op, nil
}

// func EstablishEntryORHop() error {

// 	// Generate session key pair
// 	sessionPrivKey, sessionPubKey, err := crypto.GenerateKeyPair(curve)
// 	if err != nil {
// 		slog.Warn("Failed to generate session key pair", "Err", err)
// 		return []byte{}, err
// 	}

// 	createCellPayload := protocol.CreateCellPayload{
// 		PublicKey: sessionPubKey,
// 	}
// 	marshalledCreatedCellPayload, err = common.CreateCellHandler(self.CircIDCounter, &createCellPayload)
// 	if err != nil {
// 		slog.Warn("Failed to handle relay cell")
// 		return
// 	}

// 	sharedSymKey, err := common.EstablishNextHopLink(self.Curve, self.CircIDCounter, self.CurrCircuit.EntryConn)
// 	if err != nil {
// 		slog.Warn("Failed to establish entry OR hop", "Err", err)
// 		return err
// 	}
// 	// Update circ id after successful link creation
// 	self.CurrCircuit.Path[0].CircID = self.CircIDCounter
// 	self.CircIDCounter++
// 	self.CurrCircuit.Path[0].SharedSymKey = sharedSymKey

// 	return nil
// }

func EstablishCircuit() error {
	circID := self.CircIDCounter
	_, exists := self.CircuitMap[circID]
	if exists {
		slog.Warn("Circuit alread exists for", "CircID", circID)
		return errors.New("circuit alread exists")
	}
	circuit := models.Circuit{}
	// TODO: change to parse directory
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("127.0.0.1:9090")})
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("127.0.0.1:9091")})
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("127.0.0.1:9092")})

	// Establishing circuit with subsequent hops
	for i := 0; i < len(circuit.Path); i++ {

		// Generate session key pair
		sessionPrivKey, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
		if err != nil {
			slog.Warn("Failed to generate session key pair", "Err", err)
			return err
		}

		var recvdPublicKey *ecdh.PublicKey
		var recvdChecksum [protocol.SHA256ChecksumSize]byte
		if i == 0 { // Special case entry hop
			createCellPayload := protocol.CreateCellPayload{
				PublicKey: sessionPubKey,
			}
			createdCellPayload, err := common.CreateCellRT(circID, &createCellPayload, circuit.Path[0].AddrPort)
			if err != nil {
				slog.Warn("Failed to establish circuit", "Hop", 0, "Err", err)
			}
			recvdPublicKey = createdCellPayload.PublicKey
			recvdChecksum = createdCellPayload.SharedSymKeyChecksum
		} else {
			relayExtendCellPayload := protocol.RelayExtendCellPayload{
				PublicKey:  sessionPubKey,
				NextORAddr: circuit.Path[i].AddrPort,
			}
			relayExtendedCellPayload, err := common.RelayCellExtendRT(circID, &relayExtendCellPayload, &circuit, uint(i))
			if err != nil {
				slog.Warn("Failed to establish circuit", "Hop", 0, "Err", err)
			}
			recvdPublicKey = relayExtendedCellPayload.PublicKey
			recvdChecksum = relayExtendedCellPayload.SharedSymKeyChecksum
		}

		// Compute shared secret
		sharedSymKey, err := crypto.ComputeSharedSecret(sessionPrivKey, recvdPublicKey)
		if err != nil {
			slog.Warn("Failed to establish shared secret", "Hop", 0, "Err", err)
			return err
		}

		slog.Debug("shared secret", "local", sharedSymKey)

		if crypto.Hash(sharedSymKey) != recvdChecksum {
			slog.Warn("Failed to compute identical shared secrets", "local checksum", crypto.Hash(sharedSymKey), "recv checksum", recvdChecksum)
			return err
		}

		circuit.Path[i].SharedSymKey = sharedSymKey
	}

	slog.Info("Circuit Established")
	self.CircuitMap[circID] = circuit
	self.CircIDCounter++

	return nil
}

// func SendRelayExtendCell(nextHopPublicKey *ecdh.PublicKey) {
// 	// Construct the payload with OP public key (RSA encrypted) and next hop's IP (plain)
// 	// For RSA encryption, use the provided public key of the next hop
// 	// Since we're skipping the RSA encryption part, I'm directly marshalling the public key
// 	_, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
// 	// sessionPrivKey unused for now (not received any response yet)
// 	if err != nil {
// 		slog.Error("Failed to generate session key pair", "Err", err)
// 		return
// 	}
// 	nextORHop := self.CurrCircuit.Path[1]

// 	// 　Marshall Address
// 	relayExtendCellPayload := protocol.RelayExtendCellPayload{
// 		PublicKey:  sessionPubKey, // RSA_Enc(sessionPubKey, OR2's public key)
// 		NextORAddr: nextORHop.AddrPort,
// 	}

// 	marshalledExtendPayload, _ := relayExtendCellPayload.Marshall()

// 	// marshalledORHop, err := models.MarshallORHop(nextORHop)
// 	// if err != nil {
// 	// 	slog.Error("Failed to marshal nextORHop", "Err", err)
// 	// 	return err
// 	// }

// 	// marshalledPubKey, err := x509.MarshalPKIXPublicKey(sessionPubKey)
// 	// if err != nil {
// 	// 	slog.Error("Failed to marshal public key", "Err", err)
// 	// 	return err
// 	// }

// 	// // Data = ORHop + PubKey
// 	// dataPayload := append(marshalledPubKey, marshalledORHop...)

// 	// // Truncate or pad the payload as necessary to fit the relay cell size
// 	// if len(dataPayload) < protocol.RelayPayloadSize {
// 	// 	dataPayload = append(dataPayload, make([]byte, protocol.RelayPayloadSize-len(dataPayload))...)
// 	// } else {
// 	// 	dataPayload = dataPayload[:protocol.RelayPayloadSize]
// 	// }

// 	digest := crypto.HashDigest(marshalledExtendPayload)

// 	// Construct the relay cell payload
// 	relayPayload := protocol.RelayCellPayload{
// 		StreamID: 0, // TODO: Set the StreamID if needed in the future
// 		Digest:   [protocol.DigestSize]byte(digest),
// 		Len:      uint16(len(marshalledExtendPayload)),
// 		Cmd:      protocol.Extend,
// 	}
// 	copy(relayPayload.Data[:], marshalledExtendPayload)
// 	// Encrypt the payload using the shared symmetric key with the Entry OR
// 	sharedSecret := self.CurrCircuit.Path[0].SharedSymKey
// 	marshalledPayload, err := relayPayload.Marshall()
// 	if err != nil {
// 		slog.Error("Failed to marshall relay payload", "Err", err)
// 		return
// 	}
// 	encryptedRelayPayload, err := crypto.EncryptData(sharedSecret, marshalledPayload[:])
// 	if err != nil {
// 		slog.Error("Failed to encrypt marshalled relay payload", "Err", err)
// 		return
// 	}

// 	// Create a relay cell and send it
// 	relayCell := protocol.Cell{
// 		CircID: self.CurrCircuit.Path[0].CircID, // Use the circuit ID for the entry node
// 		Cmd:    uint8(protocol.Relay),
// 	}
// 	copy(relayCell.Data[:], encryptedRelayPayload)

// 	relayCell.Send(self.CurrCircuit.EntryConn)

// 	respRelayCell := protocol.Cell{}
// 	respRelayCell.Recv(self.CurrCircuit.EntryConn)
// }

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
		case "establish-circuit", "est-ckt":
			err := EstablishCircuit()
			if err != nil {
				fmt.Println("Failed to establish circuit.")
			} else {
				fmt.Println("Circuit established")
			}
			// TODO: create circuit
		case "send":
			// destIp := words[1]
			// message := strings.Join(words[2:], " ")
			// protocol.SendTest(ipStack, destIp, message)
		default:
			fmt.Println("Invalid command:")
			// ListCommands()
		}
		fmt.Print("> ")
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Setup self instance
	var err error
	self, err = InitializeSelf()
	if err != nil {
		slog.Error("Failed to initialize self.", "Err", err)
	}

	slog.Debug("Debug", "self", *self)

	RunREPL()

	// /* TEST crypto.go */

	// /* Workflow:
	// 1. Generating a Diffie-Hellman key pair.
	// 2. Computing a shared secret using the public key from the key pair (simulating a handshake with another party).
	// 3. Hashing the shared secret to fit the size required for AES.
	// 4. Test AES: Using the hashed shared secret as a key to encrypt and decrypt data.
	// */

	// Step 1: Generate ECDH key pair for Diffie-Hellman handshake, using Alice & Bob as an example
	// curve := ecdh.P256()
	// privKey1, pubKey1, err := crypto.GenerateKeyPair(curve)
	// slog.Debug("Alice AES Private Key ", hex.EncodeToString(privKey1.Bytes()))
	// slog.Debug("Alice AES Public Key ", hex.EncodeToString(pubKey1.Bytes()))

	// privKey2, pubKey2, err := crypto.GenerateKeyPair(curve)
	// // Generate RSA key pair for Bob
	// privRSAKey2, pubRSAKey2, err := crypto.GenerateRSAKeys()

	// Encrypt and Decrypt Alice's AES public key using RSA key pair.
	// cipherKey1, err := crypto.EncryptWithPublicKey(pubKey1.Bytes(), pubRSAKey2)
	// slog.Debug("Alice RSA Encrypted her Public Key to Bob: ", hex.EncodeToString(cipherKey1))

	// decryptMsgKey1, err := crypto.DecryptWithPrivateKey(cipherKey1, privRSAKey2)

	// slog.Debug("Bob RSA Decrypted Public Key from Alice: ", hex.EncodeToString(decryptMsgKey1))

	// if bytes.Equal(pubKey1.Bytes(), decryptMsgKey1) {
	// 	slog.Info("************** RSA succeeded ***************")
	// } else {
	// 	slog.Error("************** RSA encryption failed **************")
	// }

	// // Step 2: Computing a shared secret
	// secret1, err := crypto.ComputeSharedSecret(privKey1, pubKey2)
	// if err != nil {
	// 	slog.Error("Failed to compute shared secret for Alice:", err)
	// 	return
	// }

	// secret2, err := crypto.ComputeSharedSecret(privKey2, pubKey1)
	// if err != nil {
	// 	slog.Error("Failed to compute shared secret for Bob:", err)
	// 	return
	// }

	// if bytes.Equal(secret1, secret2) {
	// 	slog.Info("************** Diffie-Hellman key exchange succeeded!************** ")
	// } else {
	// 	slog.Error("************** Diffie-Hellman key exchange failed!************** ")
	// }
	// // CONSIDER: why hash and not just use shaed secret
	// // Step 3: Hashing
	// hashedSecret := crypto.Hash(secret1)
	// hashedSecret2 := crypto.Hash(secret2)
	// if bytes.Equal(hashedSecret, hashedSecret2) {
	// 	slog.Info("************** Hashing is deterministic! **************")
	// } else {
	// 	slog.Error("Hashing is not deterministic!")
	// }

	// // Step 4: Test AES functions
	// // Use the hashed secret as a key to encrypt and decrypt data
	// data := []byte("This is a test message.")
	// encryptedData, err := crypto.EncryptData(data, hashedSecret)
	// if err != nil {
	// 	slog.Error("Error encrypting data:", err)
	// 	return
	// }

	// slog.Info("Encrypted Data:", hex.EncodeToString(encryptedData))

	// decryptedData, err := crypto.DecryptData(encryptedData, hashedSecret)
	// if err != nil {
	// 	slog.Error("Error decrypting data:", err)
	// 	return
	// }

	// if string(decryptedData) == string(data) {
	// 	slog.Info("************** Decryption successful!************** \n Decrypted message:", string(decryptedData))
	// } else {
	// 	slog.Error("Decryption failed. Decrypted data does not match original.")
	// }
}
