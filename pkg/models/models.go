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
}

type Circuit struct {
	Path []ORHop
}

type OnionProxy struct {
	CircIDCounter uint16
	CircuitMap    map[uint16]Circuit
	Curve         ecdh.Curve
}

type CellHandlerFunc = func(*OnionRouter, net.Conn, *protocol.Cell)
type RelayCellHandlerFunc = func(*OnionRouter, uint16, *protocol.RelayCellPayload) ([]byte, error)

type CircuitLink struct {
	SharedSymKey   []byte
	NextCircID     uint16
	NextORAddrPort netip.AddrPort
}

type OnionRouter struct {
	CircIDCounter            uint16
	Curve                    ecdh.Curve
	CircuitLinkMap           map[uint16]CircuitLink
	CellHandlerRegistry      map[protocol.CmdType]CellHandlerFunc
	RelayCellHandlerRegistry map[protocol.RelayCmdType]RelayCellHandlerFunc
}
