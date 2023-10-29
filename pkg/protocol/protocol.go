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

type RelayCmdType uint8

const (
	Data   RelayCmdType = 0
	Extend RelayCmdType = 1
)

type Cell struct {
	CircID uint16
	Cmd    uint8
	Data   []byte
}

type CreateCellPayload struct {
	Msg string
}

type RelayCellPayload struct {
	StreamID uint16
	Digest   [DigestSize]byte
	Len      uint16
	Cmd      uint8
	Data     []byte
}

// CreateCell represents a CREATE cell.
type CreateCell struct {
	CircID  uint16
	Cmd     uint8
	Payload CreateCellPayload
}

// NewCreateCell creates a new CREATE cell.
func NewCreateCell(circID uint16, msg string) *CreateCell {
	payload := CreateCellPayload{Msg: msg}
	return &CreateCell{
		CircID: circID,
		Cmd:    uint8(Create),
		Payload: payload,
	}
}

// Marshall serializes the CREATE cell to bytes.
func (cell *CreateCell) Marshall() []byte {
	// Serialize the CREATE cell as per Tor's specification.
	// Use encoding/binary to serialize the fields.
	buf := make([]byte, 4+len(cell.Payload.Msg))
	binary.BigEndian.PutUint16(buf[:2], cell.CircID)
	buf[2] = cell.Cmd
	copy(buf[3:], []byte(cell.Payload.Msg))
	return buf
}

// Unmarshall deserializes the bytes into a CREATE cell.
func (cell *CreateCell) Unmarshall(data []byte) {
	if len(data) < 4 {
		slog.Error("Invalid CREATE cell data")
		return
	}

	cell.CircID = binary.BigEndian.Uint16(data[:2])
	cell.Cmd = data[2]
	cell.Payload.Msg = string(data[3:])
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
