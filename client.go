package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// Address of the first Onion Node in the circuit
	onionNodeAddress := "127.0.0.1:9000" // Change this to the address of the first Onion Node

	// Connect to the first Onion Node
	conn, err := net.Dial("tcp", onionNodeAddress)
	if err != nil {
		fmt.Println("Error connecting to the first Onion Node:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected to the first Onion Node")

	// Send data to the Onion network
	message := "Hello, Onion Network!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("Error sending data to the Onion Network:", err)
		return
	}

	// Receive data from the Onion network
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error receiving data from the Onion Network:", err)
		return
	}

	receivedData := string(buffer[:n])
	fmt.Println("Received:", receivedData)
}

