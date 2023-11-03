package models

import (
	"crypto/ecdh"
	"cs2390-acn/pkg/protocol"
	"net"
	"net/netip"
)

type DirectoryEntry struct {
	ID        int
	IP        string
	Port      int
	PublicKey string
}

type ORHop struct {
	AddrPort     netip.AddrPort
	SharedSymKey []byte
	CircID       uint16 // only for entry hop
}

type Circuit struct {
	EntryConn net.Conn
	Path      []ORHop
}

type OnionProxy struct {
	CurrCircuit   *Circuit
	CircIDCounter uint16
	Curve         ecdh.Curve
}

type CellHandlerFunc = func(*OnionRouter, net.Conn, *protocol.Cell)

type CircuitLink struct {
	SharedSymKey   []byte
	NextCircID     uint16
	NextORAddrPort netip.AddrPort
}

type OnionRouter struct {
	CellHandlerRegistry map[protocol.CmdType]CellHandlerFunc
	Curve               ecdh.Curve
	CircuitLinkMap      map[uint16]CircuitLink
}