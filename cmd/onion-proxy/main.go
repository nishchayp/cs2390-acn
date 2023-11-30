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
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("172.17.0.2:9090")})
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("172.17.0.3:9091")})
	circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort("172.17.0.4:9092")})	

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

func SendData(message string) error {
	// Assuming you have an established circuit, get the latest circuit ID
	circID := self.CircIDCounter - 1
	circuit, exists := self.CircuitMap[circID]
	if !exists {
		slog.Error("Failed to find the destination circuit.")
	}

	// destIP := words[1], not used for now
	relayDataPayload := protocol.RelayDataCellPayload{
		Data: message,
	}
	// TODO: currently send to the last OR in the path as destHopNum. Maybe we will choose the hop in the future.
	err := common.RelayCellDataRT(circID, &relayDataPayload, &circuit, uint(len(circuit.Path)-1))
	return err
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
			message := strings.Join(words[2:], " ")
			err := SendData(message)
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
