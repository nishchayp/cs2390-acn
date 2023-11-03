package main

import (
	"bufio"
	"crypto/ecdh"
	"cs2390-acn/pkg/handler"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
	"cs2390-acn/oniondb"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
)

// Global declaration
var self *models.OnionRouter

// Initialize the instance of Onion Router
func InitializeSelf() (*models.OnionRouter, error) {
	or := &models.OnionRouter{
		CellHandlerRegistry: make(map[protocol.CmdType]models.CellHandlerFunc),
		Curve:               ecdh.P256(),
		CircuitLinkMap:      make(map[uint16]models.CircuitLink),
	}
	// Build registry
	or.CellHandlerRegistry[protocol.Create] = handler.CreateCellHandler

	// Create a sample DirectoryEntry and Add it to oniondb:
    /*entry := models.DirectoryEntry{
        ID:        1,
        IP:        "192.168.1.100",
        Port:      8080,
        PublicKey: "sample_public_key",
    }
	_, err := oniondb.InitializeDB()
	if err != nil {
		return nil, err
	}
	oniondb.AddDataToDB(entry);*/

	return or, nil
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

// Receives a connection, recvs cell, calls the handler based on cell
func ServeClient(conn net.Conn) {
	defer conn.Close()

	// Recv a cell
	var cell protocol.Cell
	err := cell.Recv(conn)
	if err != nil {
		slog.Error("Failed to recv cell over tcp.", "Err", err)
	}

	slog.Debug("Cell", "value", cell)

	// Call the appropriate handler
	handlerFunc, ok := self.CellHandlerRegistry[protocol.CmdType(cell.Cmd)]
	if !ok {
		slog.Warn("Dropping cell", "unsuported cell cmd", cell.Cmd)
		return
	}
	handlerFunc(self, conn, &cell)

}

// Keeps on checking for client connections and serves the connection if any
func AcceptClients(tcpListner *net.TCPListener) {
	for {
		// Block until accepts a client conn
		conn, err := tcpListner.Accept()
		if err != nil {
			slog.Error("Failed to accept.", "Err", err)
		}
		go ServeClient(conn)
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

	// Set up a port to listen for tcp traffic, this would be the service's well know port
	// All clients (OP and other ORs) will connect to this port
	// TODO: pick up random node (maybe b/w 9000 - 9100), add to db
	// - ID
	// - IP
	// - Port
	// - Public key (for RSA)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", protocol.OnionListenerPort))
	if err != nil {
		slog.Error("Failed to set up a port to listen for tcp traffic.", "Err", err)
	}
	// Create a socket to listen on selected port
	tcpListner, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		log.Fatalln("Failed to create a socket to listen on selected port.", "Err", err)
	}
	defer tcpListner.Close()
	slog.Debug("Ready to accept connections")

	// In a separate thread keep on listening for any connections
	go AcceptClients(tcpListner)

	RunREPL()
}