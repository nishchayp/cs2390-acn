package protocol

import (
	"encoding/binary"
	"log/slog"
	"net"
)

const (
	DigestSize = 6
)

type CmdType uint8

const (
	Relay  CmdType = 0
	Create CmdType = 1
)

type Cell struct {
	CircID uint16
	Cmd    uint8
	Data   []byte
}

type CreateCellPayload struct {
	Msg string
}

type RelayCmdType uint8

const (
	Data   RelayCmdType = 0
	Extend RelayCmdType = 1
)

type RelayCellPayload struct {
	StreamID uint16
	Digest   [DigestSize]byte
	Len      uint16
	Cmd      uint8
	Rcmd     RelayCmdType // Updated RelayCellPayload with RelayCmdType
	Data     []byte
}

// CreateCell represents a CREATE cell.
type CreateCell struct {
	CircID  uint16
	Cmd     uint8
	Payload CreateCellPayload
}

// RelayCell represents a RELAY cell.
type RelayCell struct {
	CircID  uint16
	Cmd     uint8
	Payload RelayCellPayload
}

// NewRelayCell creates a new RELAY cell.
func NewRelayCell(circID, streamID uint16, digest [DigestSize]byte, rcmd RelayCmdType, data []byte) *RelayCell {
	payload := RelayCellPayload{
		StreamID: streamID,
		Digest:   digest,
		Len:      uint16(len(data)),
		Cmd:      uint8(Relay),
		Rcmd:     rcmd,
		Data:     data,
	}
	return &RelayCell{
		CircID:  circID,
		Cmd:     uint8(Relay),
		Payload: payload,
	}
}

// Marshall serializes the RELAY cell to bytes.
func (cell *RelayCell) Marshall() []byte {
	// Serialize the RELAY cell as per Tor's specification.
	buf := make([]byte, 9+len(cell.Payload.Data))
	binary.BigEndian.PutUint16(buf[:2], cell.CircID)
	binary.BigEndian.PutUint16(buf[2:4], cell.Payload.StreamID)
	copy(buf[4:10], cell.Payload.Digest[:])
	binary.BigEndian.PutUint16(buf[10:12], cell.Payload.Len)
	buf[12] = cell.Payload.Cmd
	buf[13] = cell.Payload.Rcmd // Added serialization of RelayCmdType
	copy(buf[14:], cell.Payload.Data)
	return buf
}

// Unmarshall deserializes the bytes into a RELAY cell.
func (cell *RelayCell) Unmarshall(data []byte) {
	if len(data) < 13 {
		slog.Error("Invalid RELAY cell data")
		return
	}

	cell.CircID = binary.BigEndian.Uint16(data[:2])
	cell.Payload.StreamID = binary.BigEndian.Uint16(data[2:4])
	copy(cell.Payload.Digest[:], data[4:10])
	cell.Payload.Len = binary.BigEndian.Uint16(data[10:12])
	cell.Payload.Cmd = data[12]
	cell.Payload.Rcmd = RelayCmdType(data[13]) // Added deserialization of RelayCmdType
	cell.Payload.Data = data[14:]
}

// SendRelayCell sends a RELAY cell over a network connection.
func SendRelayCell(conn net.Conn, cell *RelayCell) {
	cellData := cell.Marshall()
	SendCell(conn, cellData)
}

// SendCreateCell sends a CREATE cell over a network connection.
func SendCreateCell(conn net.Conn, cell *CreateCell) {
	cellData := cell.Marshall()
	SendCell(conn, cellData)
}

func SendCell(conn net.Conn, cellData []byte) {
	n, err := conn.Write(cellData)
	slog.Info("Bytes sent: ", n)
	if err != nil {
		slog.Error("Failed to send cell. Error: ", err)
	}
}

// CHECK: What's cellData param here? is it RelayCellPayload or just Digest + Len + Cmd + Data?
func SendEncryptedCell(conn net.Conn, cellData []byte, key []byte) {
	// Encrypt the data before sending.
	encryptedData, err := EncryptData(cellData, key)
	if err != nil {
		slog.Error("Failed to encrypt cell data. Error:", err)
		return
	}

	n, err := conn.Write(encryptedData)
	slog.Info("Bytes sent:", n)
	if err != nil {
		slog.Error("Failed to send encrypted cell. Error:", err)
	}
}
