package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// Onion Node Configuration
	nodePort := ":9000" // Change this to your desired port
	nextNodeAddress := "127.0.0.1:9001" // Change this to the address of the next Onion Node

	// Create a listener to accept incoming connections
	listen, err := net.Listen("tcp", nodePort)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer listen.Close()
	fmt.Printf("Onion Node listening on %s\n", nodePort)

	for {
		// Accept incoming client connections
		clientConn, err := listen.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		// Connect to the next Onion Node in the circuit
		nextNodeConn, err := net.Dial("tcp", nextNodeAddress)
		if err != nil {
			fmt.Println("Error connecting to the next node:", err)
			clientConn.Close()
			continue
		}

		// Start a goroutine to relay data from the client to the next node
		go relayData(clientConn, nextNodeConn)
	}
}

// Relay data from the client to the next node
func relayData(clientConn, nextNodeConn net.Conn) {
	defer clientConn.Close()
	defer nextNodeConn.Close()

	buffer := make([]byte, 1024)
	for {
		// Read data from the client
		n, err := clientConn.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from client:", err)
			break
		}

		// Forward the data to the next node
		_, err = nextNodeConn.Write(buffer[:n])
		if err != nil {
			fmt.Println("Error writing to the next node:", err)
			break
		}
	}
}

