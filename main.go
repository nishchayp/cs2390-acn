package main

import (
	"fmt"
	"time"
)

func main() {
	// Create and start an Onion Node
	node := NewOnionNode("Node 1")
	go node.Start()

	// Simulate a client sending a message to the Onion network
	go func() {
		client := NewOnionClient("Client 1", node)
		client.SendMessage("Hello, Onion Network!")
	}()

	// Simulate another client sending a message
	go func() {
		client := NewOnionClient("Client 2", node)
		client.SendMessage("This is another message.")
	}()

	// Keep the main program running
	for {
		select {
		case msg := <-node.ReceivedMessages:
			fmt.Printf("Received Message: %s\n", msg)
		}
		time.Sleep(time.Second)
	}
}
