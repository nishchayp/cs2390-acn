package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
)

const (
	OnionListenerPort = 9090
	CellSize          = 512
	CellHeaderSize    = 3
	CellPayloadSize   = 509
	RelayHeaderSize   = 11
	RelayPayloadSize  = 498
	DigestSize        = 6
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
	Data   [CellPayloadSize]byte
}

type RelayCellPayload struct {
	StreamID uint16
	Digest   [DigestSize]byte
	Len      uint16
	Cmd      RelayCmdType
	Data     [RelayPayloadSize]byte
}

type CreateCellPayload struct {
	MsgSize uint8
	Msg     string
}

// // CreateCell represents a CREATE cell.
// type CreateCell struct {
// 	CircID  uint16
// 	Cmd     uint8
// 	Payload CreateCellPayload
// }

// // RelayCell represents a RELAY cell.
// type RelayCell struct {
// 	CircID  uint16
// 	Cmd     uint8
// 	Payload RelayCellPayload
// }

// // NewCreateCell creates a new CREATE cell.
// func NewCreateCell(circID uint16, msg string) *CreateCell {
// 	payload := CreateCellPayload{Msg: msg}
// 	return &CreateCell{
// 		CircID:  circID,
// 		Cmd:     uint8(Create),
// 		Payload: payload,
// 	}
// }

// // NewRelayCell creates a new RELAY cell.
// func NewRelayCell(circID, streamID uint16, digest [DigestSize]byte, cmd RelayCmdType, data []byte) *RelayCell {
// 	payload := RelayCellPayload{
// 		StreamID: streamID,
// 		Digest:   digest,
// 		Len:      uint16(len(data)),
// 		Cmd:      cmd,
// 		Data:     data,
// 	}
// 	return &RelayCell{
// 		CircID:  circID,
// 		Cmd:     uint8(Relay),
// 		Payload: payload,
// 	}
// }

// Unmarshall deserializes the bytes into a CELL.
func (cell *Cell) Unmarshall(data []byte) error {
	if len(data) < CellSize {
		slog.Warn("Invalid cell data")
		return errors.New("Incorrect number of bytes recv")
	}
	cell.CircID = binary.BigEndian.Uint16(data[:2])
	cell.Cmd = data[3]
	cell.Data = [509]byte(data[4:])
	copy(cell.Data[:], data[4:])
	return nil
}

// Recv a cell over a tcp connection
func (cell *Cell) Recv(conn net.Conn) error {
	// Recv over tcp
	buf := make([]byte, CellSize)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		slog.Warn("Failed to read. Error: ", err)
		return err
	}

	// Convert bytes recv to cell struct
	err = cell.Unmarshall(buf)
	if err != nil {
		slog.Warn("Failed to unmarshall. Error: ", err)
		return err
	}
	return nil
}

// // Marshall serializes the RELAY cell to bytes.
// func (cell *RelayCell) Marshall() []byte {
// 	// Serialize the RELAY cell as per Tor's specification.
// 	buf := make([]byte, 9+len(cell.Payload.Data))
// 	binary.BigEndian.PutUint16(buf[:2], cell.CircID)
// 	binary.BigEndian.PutUint16(buf[2:4], cell.Payload.StreamID)
// 	copy(buf[4:10], cell.Payload.Digest[:])
// 	binary.BigEndian.PutUint16(buf[10:12], cell.Payload.Len)
// 	// buf[12] = cell.Payload.Cmd
// 	copy(buf[13:], cell.Payload.Data)
// 	return buf
// }

// // Unmarshall deserializes the bytes into a RELAY cell.
// func (cell *RelayCell) Unmarshall(data []byte) {
// 	if len(data) < 13 {
// 		slog.Error("Invalid RELAY cell data")
// 		return
// 	}

// 	cell.CircID = binary.BigEndian.Uint16(data[:2])
// 	cell.Payload.StreamID = binary.BigEndian.Uint16(data[2:4])
// 	copy(cell.Payload.Digest[:], data[4:10])
// 	cell.Payload.Len = binary.BigEndian.Uint16(data[10:12])
// 	cell.Payload.Cmd = RelayCmdType(data[12])
// 	cell.Payload.Data = data[13:]
// }

// // SendRelayCell sends a RELAY cell over a network connection.
// func SendRelayCell(conn net.Conn, cell *RelayCell) {
// 	cellData := cell.Marshall()
// 	SendCell(conn, cellData)
// }

// // Marshall serializes the CREATE cell to bytes.
// func (cell *CreateCell) Marshall() []byte {
// 	// Serialize the CREATE cell as per Tor's specification.
// 	// Use encoding/binary to serialize the fields.
// 	buf := make([]byte, 4+len(cell.Payload.Msg))
// 	binary.BigEndian.PutUint16(buf[:2], cell.CircID)
// 	buf[2] = cell.Cmd
// 	copy(buf[3:], []byte(cell.Payload.Msg))
// 	return buf
// }

// // Unmarshall deserializes the bytes into a CREATE cell.
// func (cell *CreateCell) Unmarshall(data []byte) {
// 	if len(data) < 4 {
// 		slog.Error("Invalid CREATE cell data")
// 		return
// 	}

// 	cell.CircID = binary.BigEndian.Uint16(data[:2])
// 	cell.Cmd = data[2]
// 	cell.Payload.Msg = string(data[3:])
// }

// // SendCreateCell sends a CREATE cell over a network connection.
// func SendCreateCell(conn net.Conn, cell *CreateCell) {
// 	cellData := cell.Marshall()
// 	SendCell(conn, cellData)
// }

// func SendCell(conn net.Conn, cellData []byte) {
// 	n, err := conn.Write(cellData)
// 	slog.Info("Bytes sent: ", n)
// 	if err != nil {
// 		slog.Error("Failed to send cell. Error: ", err)
// 	}
// }

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
