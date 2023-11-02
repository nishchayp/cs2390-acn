package main

import (
	"bufio"
	"cs2390-acn/pkg/handler"
	"cs2390-acn/pkg/protocol"
	//"cs2390-acn/cmd/directory"
	"cs2390-acn/oniondb"
	"strconv"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
    _ "github.com/mattn/go-sqlite3" // importing sqlite driver code
)

// self
type OnionRouter struct {
	CellHandlerRegistry map[protocol.CmdType]handler.CellHandlerFunc
}

// Initialize the instance of Onion Router
func (or *OnionRouter) Initialize() error {
	// Build registry
	or.CellHandlerRegistry = make(map[protocol.CmdType]func(net.Conn, *protocol.Cell))
	or.CellHandlerRegistry[protocol.Create] = handler.CreateCellHandler

	// Set up a port to listen for tcp traffic, this would be the service's well know port
	// All clients (OP and other ORs) will connect to this port
	// TODO: pick up random node (maybe b/w 9000 - 9100), add to db
	// - ID
	// - IP
	// - Port
	// - Public key (for RSA)
	// Generate or obtain the values to be added to the database (replace w/ actual values)

	// Initialize the database
	//_, err := oniondb.InitializeDB()

	dbID, _ := strconv.Atoi(os.Args[1])//9000
	dbIP := os.Args[1]//"192.168.1.2"
	dbPort := 9001//strconv.Atoi(os.Args[1])//protocol.OnionListenerPort//9001
	dbPublicKey := "pk_test2"

	// Add the generated values to the database
	err := oniondb.AddDataToDB(dbID, dbIP, dbPort, dbPublicKey)
	if err != nil {
		log.Printf("Failed to add data to the database: %v", err)
		return err
	}
	return nil
}

// Global declaration
var self *OnionRouter

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
		slog.Error("Failed to recv cell over tcp. Err: ", err)
	}

	// Call the appropriate handler
	handlerFunc, ok := self.CellHandlerRegistry[protocol.CmdType(cell.Cmd)]
	if !ok {
		slog.Warn("Dropping cell, unsuported cell cmd: ", cell.Cmd)
		return
	}
	handlerFunc(conn, &cell)

}

// Keeps on checking for client connections and serves the connection if any
func AcceptClients(tcpListner *net.TCPListener) {
	for {
		// Block until accepts a client conn
		conn, err := tcpListner.Accept()
		if err != nil {
			slog.Error("Failed to accept. Err: ", err)
		}
		go ServeClient(conn)
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	// Setup self instance
	self := &OnionRouter{}
	err := self.Initialize()
	if err != nil {
		slog.Error("Failed to initialize self. Err: ", err)
	}


	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%s", protocol.OnionListenerPort))
	if err != nil {
		slog.Error("Failed to set up a port to listen for tcp traffic. Err: ", err)
	}
	// Create a socket to listen on selected port
	tcpListner, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		log.Fatalln("Failed to create a socket to listen on selected port. Err: ", err)
	}
	defer tcpListner.Close()
	slog.Debug("Ready to accept connections")

	// In a separate thread keep on listening for any connections
	go AcceptClients(tcpListner)

	RunREPL()
}
