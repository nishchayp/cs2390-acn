# cs2390-acn

This Go-based project simulates a basic onion routing system, comprising two main components: onion-proxy and onion-router. The onion-proxy is responsible for creating encrypted circuits and relaying data, while the onion-router serves as a network node that handles circuit extension and data relay.

The onion-proxy component showcases the use of AES encryption and Diffie-Hellman key exchange for securing data transmission. It also demonstrates the creation, extension, and relay of onion routing circuits. The onion-router component establishes a TCP server, allowing clients to interact via a simple command-line REPL interface

## Demo


https://github.com/nishchayp/cs2390-acn/assets/23032266/5f5574a6-be2c-4d1e-8f06-3c9ecfbf3854



## Startup and showcase

A sample topology has been configured for ease of use, the file `docker-compose.yml` configures an Onion Proxy (client) and 5 Onion Routers (relays). You can build using:
```
docker-compose up --build 
```

One can then act as a client by attaching to the running Onion Proxy (client) container
```
docker attach op_container
```

Below we present a scenario to showcase the capabilities of our system 
```
// Establishes circuit and sends https request
est-ckt
show-circuit
send 0 https://httpbin.org/get

// Teardown and establish a new circuit
teardown
show-circuit
est-ckt
show-circuit
send 1 https://httpbin.org/get
```

The containers could then be torn down using.
```
docker-compose down 
```
