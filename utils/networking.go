package main

import (
	"fmt"
	"net"
)

func startServer() {
	listen, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listen.Close()

	fmt.Println("Server is listening on port 8080")

	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println("Connection error:", err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Client read error:", err)
		return
	}

	data := buffer[:n]
	fmt.Println("Received:", string(data))

	// Process the data here, e.g., send it to the next node in the onion network.

	// Respond to the client
	response := []byte("Server response: Thank you for your message!\n")
	_, err = conn.Write(response)
	if err != nil {
		fmt.Println("Server write error:", err)
	}
}

func startClient() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("Error connecting to the server:", err)
		return
	}
	defer conn.Close()

	message := []byte("Hello, server! This is the client.\n")
	_, err = conn.Write(message)
	if err != nil {
		fmt.Println("Client write error:", err)
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Client read error:", err)
		return
	}

	response := buffer[:n]
	fmt.Println("Server response:", string(response))
}

func main() {
	go startServer()
	startClient()

	// Keep the application running
	select {}
}
