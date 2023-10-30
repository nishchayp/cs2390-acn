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

func SendCell(conn net.Conn, cellData []byte) {
	n, err := conn.Write(cellData)
	slog.Info("Bytes sent: ", n)
	if err != nil {
		slog.Error("Failed to send cell. Error: ", err)
	}
}

// CHECK: What's cellData param here? is it RelayCellPayload or just Digest + Len + Cmd + Data?
// func SendEncryptedCell(conn net.Conn, cellData []byte, key []byte) {
// 	// Encrypt the data before sending.
// 	encryptedData, err := EncryptData(cellData, key)
// 	if err != nil {
// 		slog.Error("Failed to encrypt cell data. Error:", err)
// 		return
// 	}

// 	n, err := conn.Write(encryptedData)
// 	slog.Info("Bytes sent:", n)
// 	if err != nil {
// 		slog.Error("Failed to send encrypted cell. Error:", err)
// 	}
// }
