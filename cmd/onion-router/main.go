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
	"text/tabwriter"
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
	or.CellHandlerRegistry[protocol.Destroy] = handler.DestroyCellHandler

	// Build RelayCellHandlerRegistry registry
	or.RelayCellHandlerRegistry[protocol.Extend] = handler.RelayCellExtendHandler
	or.RelayCellHandlerRegistry[protocol.Data] = handler.RelayCellDataHandler

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
		case "show-links":
			w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
			fmt.Fprintf(w, "\t%s\t%s\t%s\n", "Recd CircID", "Next CircID", "Next OR Addr")
			for circID, link := range self.CircuitLinkMap {
				fmt.Fprintf(w, "\t%d\t%d\t%s\n", circID, link.NextCircID, link.NextORAddrPort)
			}
			w.Flush()
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
	fmt.Fprintf(w, "\t%s\t%s\n", "show-links", "Print out circuit links with this OR")
	w.Flush()
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

	slog.Debug("Received Cell!!!", "Cmd", cell.Cmd, "Data", cell.Data, "value", cell)

	// Call the appropriate handler
	handlerFunc, ok := self.CellHandlerRegistry[protocol.CmdType(cell.Cmd)]
	if !ok {
		slog.Warn("Dropping cell", "unsupported cell cmd", cell.Cmd)
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

	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <servername>", os.Args[0])
	}
	servername := os.Args[1]

	// Setup self instance
	var err error
	self, err = InitializeSelf()
	if err != nil {
		slog.Error("Failed to initialize self.", "Err", err)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s", servername))
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
