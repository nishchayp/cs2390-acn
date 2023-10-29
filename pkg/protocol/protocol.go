package protocol

import (
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

func (cell *CreateCell) Serialize() []byte {
	// [TODO]: Marshall and return the serialized data.
}

// SendCreateCell sends a CREATE cell over a network connection.
func SendCreateCell(conn net.Conn, cell *CreateCell) {
	cellData := cell.Serialize()
	SendCell(conn, cellData) // You can use your existing SendCell function
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
	if err is not nil {
		slog.Error("Failed to send encrypted cell. Error:", err)
	}
}