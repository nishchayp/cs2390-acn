# cs2390-acn

This Go-based project simulates a basic onion routing system, comprising two main components: onion-proxy and onion-router. The onion-proxy is responsible for creating encrypted circuits and relaying data, while the onion-router serves as a network node that handles circuit extension and data relay. The project also includes a pkg/protocol package for cryptographic operations.

The onion-proxy component showcases the use of AES encryption and Diffie-Hellman key exchange for securing data transmission. It also demonstrates the creation, extension, and relay of onion routing circuits. The onion-router component establishes a TCP server, allowing clients to interact via a simple command-line REPL interface