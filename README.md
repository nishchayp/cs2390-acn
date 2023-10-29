# Simple Onion Routing Network in Go

This is a basic implementation of an Onion routing network in Go. It is intended for educational purposes and demonstrates the core components of an Onion routing system.

## Components

1. `node.go`: This file contains the implementation of the Onion Node. An Onion Node is a network node that routes messages through the network. The node.go file defines the `OnionNode` struct and methods for starting and running the node.

2. `client.go`: This file contains the implementation of an Onion Client. An Onion Client is a user or application that wants to send a message through the Onion network. The `OnionClient` struct and methods are defined in this file.

3. `encryption.go`: This file contains basic encryption and decryption functions used in the Onion network. It includes functions for encrypting and decrypting messages with symmetric keys.

4. `networking.go`: This file defines the networking aspects of the Onion network, such as sending and receiving messages between nodes and clients. It also includes data structures to represent the network state.

5. `main.go`: The main program file. It creates an Onion Node, simulates client messages, and receives and displays messages routed through the network.

## How to Use

1. Clone this repository to your local machine.

2. Ensure you have Go installed on your system.

3. Open a terminal and navigate to the project directory.

4. Run the following command to execute the program:

   ```bash
   go run main.go
