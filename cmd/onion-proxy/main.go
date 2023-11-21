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
			relayExtendedCellPayload, err := common.RelayCellExtendRT(circID, &relayExtendCellPayload, &circuit, uint(i-1))
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
		slog.Info("[ADD to Circuit]", "i", i, ", circuit.Path[i] with sharedKey", circuit.Path[i])
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
			fmt.Printf("Circuit ID Counter: %d\n", self.CircIDCounter)
			fmt.Printf("CircuitMap: %s\n", self.CircuitMap)
			fmt.Printf("Curve: %s\n", self.Curve)
			//fmt.Printf("CellHandlerRegistry: %s\n", self.CellHandlerRegistry)
			//fmt.Printf("RelayCellHandlerRegistry: %s\n", self.RelayCellHandlerRegistry)
		case "establish-circuit", "est-ckt":
			err := EstablishCircuit()
			if err != nil {
				fmt.Println("Failed to establish circuit.")
			} else {
				fmt.Println("Circuit established")
			}
			// TODO: create circuit
		case "send":
			if len(words) < 3 {
				fmt.Println("Invalid command. Usage: send <destination IP> <message>")
				break
			}
		
			// Assuming you have an established circuit, get the latest circuit ID
			circID := self.CircIDCounter - 1
			circuit, exists := self.CircuitMap[circID]
			if !exists {
				fmt.Println("No established circuit.")
				break
			}
		
			//destIP := words[1]
			message := strings.Join(words[2:], " ")
		
			// Create a RelayCellPayload with the message
			relayPayload := protocol.RelayCellPayload{
				StreamID: 0, // You may need to assign a unique stream ID
				Digest:   crypto.HashDigest([]byte(message)),
				Len:      uint16(len(message)),
				Cmd:      protocol.Data,
			}
			copy(relayPayload.Data[:], []byte(message))
		
			_, err := common.RelayCellRT(circID, &relayPayload, &circuit, uint(len(circuit.Path)-1))
			if err != nil {
				fmt.Println("Failed to send message through the circuit.", err)
			} else {
				fmt.Println("Message sent through the circuit.")
			}
		
		default:
			fmt.Println("Invalid command:")
			// ListCommands()
		}
		fmt.Print("> ")
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	// Setup self instance
	var err error
	self, err = InitializeSelf()
	if err != nil {
		slog.Error("Failed to initialize self.", "Err", err)
	}

	slog.Debug("Debug", "self", *self)

	RunREPL()
}
