package models

import (
	"crypto/ecdh"
	"cs2390-acn/pkg/protocol"
	"net"
	"net/netip"
)

var addrPortBytesSize = 16

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

// // MarshallORHop converts ORHop into bytes.
// func MarshallORHop(orph ORHop) ([]byte, error) {
// 	buf := new(bytes.Buffer)

// 	// Marlshall AddrPort
// 	addrPortBytes, err := orph.AddrPort.MarshalBinary()
// 	if err != nil {
// 		return nil, err
// 	}
// 	if _, err := buf.Write(addrPortBytes); err != nil {
// 		return nil, err
// 	}
// 	addrPortBytesSize = len(addrPortBytes)

// 	// Marshall SharedSymKey
// 	if len(orph.SharedSymKey) > 255 { // Ensuring the key length does not exceed 255 bytes
// 		slog.Warn("the key length exceeds 255 bytes")
// 		return nil, err
// 	}
// 	if err := buf.WriteByte(byte(len(orph.SharedSymKey))); err != nil {
// 		return nil, err
// 	}
// 	if _, err := buf.Write(orph.SharedSymKey); err != nil {
// 		return nil, err
// 	}

// 	// Serialize CircID
// 	if err := binary.Write(buf, binary.BigEndian, orph.CircID); err != nil {
// 		return nil, err
// 	}

// 	return buf.Bytes(), nil
// }

// // UnmarshallORHop converts bytes back into an ORHop struct.
// func UnmarshallORHop(data []byte) (ORHop, error) {
// 	buf := bytes.NewReader(data)
// 	var orph ORHop
// 	orph.CircID = 0 // No use for non-entry hops

// 	// Unmarshall AddrPort
// 	addrPortBytes := make([]byte, addrPortBytesSize)
// 	if _, err := buf.Read(addrPortBytes); err != nil {
// 		return orph, err
// 	}
// 	if err := orph.AddrPort.UnmarshalBinary(addrPortBytes); err != nil {
// 		return orph, err
// 	}

// 	// Unmarshall SharedSymKey
// 	orph.SharedSymKey = make([]byte, crypto.AESKeySize)
// 	if _, err := buf.Read(orph.SharedSymKey); err != nil {
// 		return orph, err
// 	}

// 	// Deserialize CircID
// 	if err := binary.Read(buf, binary.BigEndian, &orph.CircID); err != nil {
// 		return orph, err
// 	}

// 	// If there is any remaining data in the buffer after reading CircID, it's an error
// 	if buf.Len() > 0 {
// 		slog.Warn("excess data after unmarshalling ORHop")
// 		return orph, nil
// 	}

// 	return orph, nil
// }
package models

import (
	"crypto/ecdh"
	"cs2390-acn/pkg/protocol"
	"net"
	"net/netip"
)

type DirectoryEntry struct {
	ID        uint16
	IP        netip.AddrPort
	Port      uint16
	PublicKey *ecdh.PublicKey
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