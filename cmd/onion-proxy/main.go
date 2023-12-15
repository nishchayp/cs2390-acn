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
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
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

// Create a circuit by sending create and then relay extend cells down the ckt
func EstablishCircuit() (uint16, error) {
	circID := self.CircIDCounter
	_, exists := self.CircuitMap[circID]
	if exists {
		slog.Warn("Circuit alread exists for", "CircID", circID)
		return 0, errors.New("circuit alread exists")
	}
	circuit := models.Circuit{}

	directory, err := os.ReadFile("directory.csv")
	if err != nil {
		slog.Warn("Failed to read directory", "Err", err)
		return protocol.InvalidCircId, err
	}
	ipAddresses := strings.Split(string(directory), ",")

	rand.Shuffle(len(ipAddresses), func(i, j int) { ipAddresses[i], ipAddresses[j] = ipAddresses[j], ipAddresses[i] })
	for _, chosenIP := range ipAddresses[:3] {
		circuit.Path = append(circuit.Path, models.ORHop{AddrPort: netip.MustParseAddrPort(chosenIP)})
	}

	// Establishing circuit with subsequent hops
	for i := 0; i < len(circuit.Path); i++ {

		// Generate session key pair
		sessionPrivKey, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
		if err != nil {
			slog.Warn("Failed to generate session key pair", "Err", err)
			return protocol.InvalidCircId, err
		}

		var recvdPublicKey *ecdh.PublicKey
		var recvdChecksum [protocol.SHA256ChecksumSize]byte
		if i == 0 { // Special case entry hop
			createCellPayload := protocol.CreateCellPayload{
				PublicKey: sessionPubKey,
			}
			createdCellPayload, err := common.CreateCellRT(circID, &createCellPayload, circuit.Path[0].AddrPort)
			if err != nil {
				slog.Warn("Failed to establish circuit", "Hop", i, "Err", err)
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
				slog.Warn("Failed to establish circuit", "Hop", i, "Err", err)
			}
			recvdPublicKey = relayExtendedCellPayload.PublicKey
			recvdChecksum = relayExtendedCellPayload.SharedSymKeyChecksum
		}

		// Compute shared secret
		sharedSymKey, err := crypto.ComputeSharedSecret(sessionPrivKey, recvdPublicKey)
		if err != nil {
			slog.Warn("Failed to establish shared secret", "Hop", 0, "Err", err)
			return protocol.InvalidCircId, err
		}

		slog.Debug("shared secret", "local", sharedSymKey)

		if crypto.Hash(sharedSymKey) != recvdChecksum {
			slog.Warn("Failed to compute identical shared secrets", "local checksum", crypto.Hash(sharedSymKey), "recv checksum", recvdChecksum)
			return protocol.InvalidCircId, err
		}

		circuit.Path[i].SharedSymKey = sharedSymKey
		slog.Debug("[ADD to Circuit]", "i", i, ", circuit.Path[i] with sharedKey", circuit.Path[i])
	}

	slog.Debug("Circuit Established")
	self.CircuitMap[circID] = circuit
	self.CircIDCounter++

	return circID, nil
}

func SendData(circID uint16, message string) error {
	// Assuming you have an established circuit, get the latest circuit ID
	circuit, exists := self.CircuitMap[circID]
	if !exists {
		slog.Error("Failed to find the destination circuit.")
		return errors.New("invalid circid")
	}

	relayDataPayload := protocol.RelayDataCellPayload{
		Data: message,
	}
	// TODO: currently send to the last OR in the path as destHopNum. Maybe we will choose the hop in the future.
	respRelayDataPayload, err := common.RelayCellDataRT(circID, &relayDataPayload, &circuit, uint(len(circuit.Path)-1))
	fmt.Printf("Response: %s\n", respRelayDataPayload.Data)
	return err
}

// Prints put the circuit
func ShowCircuit(circID uint16) {
	ckt, exists := self.CircuitMap[circID]
	if !exists {
		slog.Error("Invalid circID")
		return
	}
	fmt.Printf("CircId-%d = ", circID)
	for idx, or := range ckt.Path {
		fmt.Printf("OR-%d <%s> -> ", idx, or.AddrPort)
	}
	fmt.Println("/")
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
			if len(words) == 1 {
				for circId := range self.CircuitMap {
					ShowCircuit(circId)
				}
			} else {
				circId, err := strconv.Atoi(words[1])
				if err != nil {
					slog.Error("Invalid circID")
				} else {
					ShowCircuit(uint16(circId))
				}
			}
		case "establish-circuit", "est-ckt":
			circId, err := EstablishCircuit()
			if err != nil {
				slog.Error("Failed to establish circuit.")
				fmt.Print("> ")
				continue
			}
			fmt.Printf("Circuit established. CircId: %d\n", circId)
		case "send":
			if len(words) < 3 {
				fmt.Println("Invalid command. Usage: send <circId> <message>")
				break
			}
			circId, err := strconv.Atoi(words[1])
			if err != nil {
				slog.Error("Invalid circID")
				fmt.Print("> ")
				continue
			}
			message := strings.Join(words[2:], " ")
			err = SendData(uint16(circId), message)
			if err != nil {
				slog.Error("Failed to send message through the circuit.", "Err", err)
			}
		default:
			fmt.Println("Invalid command:")
			ListCommands()
		}
		fmt.Print("> ")
	}
}

func ListCommands() {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "Commands\n")
	fmt.Fprintf(w, "\t%s\t%s\n", "exit", "Terminate this program")
	fmt.Fprintf(w, "\t%s\t%s\n", "show-circuit", "Print out the circuit path")
	fmt.Fprintf(w, "\t%s\t%s\n", "send", "Send data to exit OR")
	w.Flush()
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
}
