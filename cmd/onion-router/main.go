package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
)

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

func ServeClient(conn net.Conn) {
	defer conn.Close()

	slog.Debug("Serving client")

	buf := make([]byte, 5)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		slog.Error("Failed to read. Error: ", err)
	}
	fmt.Println(string(buf))
}

func AcceptClients(tcpListner *net.TCPListener) {
	for {
		// Block until accepts a client conn
		slog.Debug("before accept")
		conn, err := tcpListner.Accept()
		slog.Debug("after accept")
		if err != nil {
			slog.Error("Failed to accept. Err: ", err)
		}
		go ServeClient(conn)
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	if len(os.Args) != 2 {
		slog.Error("usage: %s <tcpport>", os.Args[0])
	}
	tcpport := os.Args[1]

	// Set up a port to listen for tcp traffic
	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%s", tcpport))
	if err != nil {
		log.Fatalln("Failed to set up a port to listen for tcp traffic. Err: ", err)
	}

	// Create a socket to listen on selected port
	tcpListner, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		log.Fatalln("Failed to create a socket to listen on selected port. Err: ", err)
	}
	defer tcpListner.Close()

	slog.Debug("Ready to accept")

	go AcceptClients(tcpListner)

	RunREPL()
}