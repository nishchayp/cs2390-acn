package main

import (
	"bufio"
	"crypto/ecdh"
	"cs2390-acn/pkg/handler"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
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
		CircIDCounter:            0,
		Curve:                    ecdh.P256(),
		CircuitLinkMap:           make(map[uint16]models.CircuitLink),
		CellHandlerRegistry:      make(map[protocol.CmdType]models.CellHandlerFunc),
		RelayCellHandlerRegistry: make(map[protocol.RelayCmdType]models.RelayCellHandlerFunc),
	}
	// Build CellHandlerRegistry registry
	or.CellHandlerRegistry[protocol.Create] = handler.CreateCellHandler
	or.CellHandlerRegistry[protocol.Relay] = handler.RelayCellHandler

	// Build RelayCellHandlerRegistry registry
	or.RelayCellHandlerRegistry[protocol.Extend] = handler.RelayCellExtendHandler
	or.RelayCellHandlerRegistry[protocol.Data] = handler.RelayCellDataHandler

	return or, nil
}

func RunREPL() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	slog.Debug("Reached debug after checkpoint 1234")
	for scanner.Scan() {
		slog.Debug("Reached debug after checkpoint 1235")
		line := scanner.Text()
		words := strings.Split(line, " ")
		cmd := words[0]
		switch cmd {
		case "exit":
			os.Exit(0)
		case "show-circuit":
			fmt.Println("Current circuit path:")
			for circID, link := range self.CircuitLinkMap {
				fmt.Printf("Circuit ID: %d\n", circID)
				//fmt.Printf("Link: %s\n", link)
				fmt.Printf("SymKey: %s\n", link.SharedSymKey)
				fmt.Printf("Next Circ ID: %d\n", link.NextCircID)
				fmt.Printf("Next port: %s\n", link.NextORAddrPort)
				fmt.Println("----------------------")
			}
		case "establish-circuit":
			// TODO: create circuit
		case "send":
			// destIp := words[1]
			// message := strings.Join(words[2:], " ")
			// protocol.SendTest(ipStack, destIp, message)
		case "display-metadata": // Temporary for debugging ORs
			fmt.Printf("Circuit ID Counter: %d\n", self.CircIDCounter)
			fmt.Printf("Curve: %s\n", self.Curve)
			fmt.Printf("CircuitLinkMap: %s\n", self.CircuitLinkMap)
			fmt.Printf("CellHandlerRegistry: %s\n", self.CellHandlerRegistry)
			fmt.Printf("RelayCellHandlerRegistry: %s\n", self.RelayCellHandlerRegistry)
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
		slog.Debug("Received Cell???", "Cmd", cell.Cmd, "Data", cell.Data)

		slog.Error("Failed to recv cell over tcp.", "Err", err)
	}

	//slog.Debug("Cell", "value", cell)
	slog.Debug("Received Cell!!!", "Cmd", cell.Cmd, "Data", cell.Data, "value", cell)

	// Call the appropriate handler
	handlerFunc, ok := self.CellHandlerRegistry[protocol.CmdType(cell.Cmd)]
	if !ok {
		slog.Warn("Dropping cell", "unsupported cell cmd", cell.Cmd)
		return
	}
	//slog.Debug("Handler Func", "Cmd", cell.Cmd, "Data", cell.Data, "Func", handlerFunc)

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
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <port>", os.Args[0])
	}
	port := os.Args[1]

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
	// tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", protocol.OnionListenerPort))
	//fmt.Println("Test Debug 1234")

	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%s", port))
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
	slog.Debug("Reached debug after checkpoint 123")

	RunREPL()
	slog.Debug("Reached After repl debug")

	// Block the main goroutine from exiting immediately
    for {
        // Keep the main goroutine running indefinitely
		slog.Debug("Reached debug after repl debug blocking")
    }	

}
