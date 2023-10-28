package main

import (
	"bufio"
	"cs2390-acn/pkg/protocol"
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

		fmt.Print("> ")
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	RunREPL()
}
