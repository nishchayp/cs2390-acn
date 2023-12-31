package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
)

const (
	OnionListenerPort       = 9090
	CellSize                = 512
	CellHeaderSize          = 3
	CellPayloadSize         = 509
	RelayHeaderSize         = 11
	RelayPayloadSize        = 498
	DigestSize              = 6
	PublicKeySize           = 56
	MarshalledPublicKeySize = 91
	SHA256ChecksumSize      = 32
	InvalidCircId           = math.MaxUint16
)

type CmdType uint8

const (
	Relay   CmdType = 0
	Create  CmdType = 1
	Created CmdType = 2
	Destroy CmdType = 3
)

type RelayCmdType uint8

const (
	Data     RelayCmdType = 0
	Extend   RelayCmdType = 1
	Extended RelayCmdType = 2
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
type RelayExtendCellPayload struct {
	PublicKey  *ecdh.PublicKey
	NextORAddr netip.AddrPort
}

type RelayDataCellPayload struct {
	Data string
}

type RelayExtendedCellPayload struct {
	PublicKey            *ecdh.PublicKey
	SharedSymKeyChecksum [SHA256ChecksumSize]byte
}

type CreateCellPayload struct {
	PublicKey *ecdh.PublicKey
}

type CreatedCellPayload struct {
	PublicKey            *ecdh.PublicKey
	SharedSymKeyChecksum [SHA256ChecksumSize]byte
}

/************** CellPayload **************/

// Marshall serializes the CELL to bytes.
func (cell *Cell) Marshall() ([]byte, error) {
	buf := make([]byte, CellSize)
	binary.BigEndian.PutUint16(buf[:2], cell.CircID)
	buf[2] = cell.Cmd
	copy(buf[3:], cell.Data[:])
	return buf, nil
}

// Unmarshall deserializes the bytes into a CELL.
func (cell *Cell) Unmarshall(data []byte) error {
	if len(data) < CellSize {
		slog.Warn("Invalid cell data")
		return errors.New("Incorrect number of bytes recv")
	}
	cell.CircID = binary.BigEndian.Uint16(data[:2])
	cell.Cmd = data[2]
	copy(cell.Data[:], data[3:])
	return nil
}

// Send a cell over a tcp connection
func (cell *Cell) Send(conn net.Conn) error {
	// Convert cell struct to bytes
	marshalledMsg, err := cell.Marshall()
	if err != nil {
		slog.Warn("Failed to unmarshall. Error", "Err", err)
		return err
	}

	// Send over tcp
	_, err = conn.Write(marshalledMsg)
	if err != nil {
		return err
	}
	return nil
}

// Recv a cell over a tcp connection
func (cell *Cell) Recv(conn net.Conn) error {
	// Recv over tcp
	buf := make([]byte, CellSize)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		slog.Warn("Failed to read. Error", "Err", err)
		return err
	}

	// Convert bytes recv to cell struct
	err = cell.Unmarshall(buf)
	if err != nil {
		slog.Warn("Failed to unmarshall. Error", "Err", err)
		return err
	}
	return nil
}

/************** CreateCellPayload **************/

// Marshall serializes the CreateCellPayload to bytes.
func (payload *CreateCellPayload) Marshall() ([]byte, error) {
	// var buf [CellPayloadSize]byte
	buf := make([]byte, CellPayloadSize)
	marshalledMsg, err := x509.MarshalPKIXPublicKey(payload.PublicKey)
	slog.Debug("Debug", "Marshalled key sz", len(marshalledMsg))
	if err != nil {
		slog.Warn("Failed to marshall.", "Err", err)
		return []byte{}, err
	}
	copy(buf, marshalledMsg)
	return buf, nil
}

// Unmarshall deserializes the bytes into a CreateCellPayload.
func (payload *CreateCellPayload) Unmarshall(data []byte) error {
	if len(data) < CellPayloadSize {
		slog.Warn("Invalid cell data")
		return errors.New("Incorrect number of bytes recv")
	}
	pub, err := x509.ParsePKIXPublicKey(data[:MarshalledPublicKeySize])
	if err != nil {
		slog.Warn("Failed to unmarshall, from public key")
		return err
	}
	// Assert ecdsa public key and then call ECDH on it to get ecdh pub key
	payload.PublicKey, err = pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		if err != nil {
			slog.Warn("Failed to unmarshall, from public key")
			return err
		}
	}
	return nil
}

/************** CreatedCellPayload **************/

// Marshall serializes the CreatedCellPayload to bytes.
func (payload *CreatedCellPayload) Marshall() ([]byte, error) {
	buf := make([]byte, CellPayloadSize)
	marshalledPubKey, err := x509.MarshalPKIXPublicKey(payload.PublicKey)
	if err != nil {
		slog.Warn("Failed to marshall.", "Err", err)
		return []byte{}, err
	}
	copy(buf, marshalledPubKey)
	copy(buf[MarshalledPublicKeySize:], payload.SharedSymKeyChecksum[:])
	return buf, nil
}

// Unmarshall deserializes the bytes into a CreateCellPayload.
func (payload *CreatedCellPayload) Unmarshall(data []byte) error {
	if len(data) < CellPayloadSize {
		slog.Warn("Invalid cell data")
		return errors.New("Incorrect number of bytes recv")
	}
	pub, err := x509.ParsePKIXPublicKey(data[:MarshalledPublicKeySize])
	if err != nil {
		slog.Warn("Failed to unmarshall, from public key")
		return err
	}
	// Assert ecdsa public key and then call ECDH on it to get ecdh pub key
	payload.PublicKey, err = pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		if err != nil {
			slog.Warn("Failed to unmarshall, from public key")
			return err
		}
	}
	copy(payload.SharedSymKeyChecksum[:], data[MarshalledPublicKeySize:MarshalledPublicKeySize+SHA256ChecksumSize])
	return nil
}

/************** RelayCellPayload **************/

// Marshall serializes the RelayCellPayload to bytes.
func (payload *RelayCellPayload) Marshall() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, payload.StreamID); err != nil {
		return nil, err
	}
	if _, err := buf.Write(payload.Digest[:]); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, payload.Len); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(byte(payload.Cmd)); err != nil {
		return nil, err
	}
	if _, err := buf.Write(payload.Data[:payload.Len]); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Marshall serializes the RelayCellPayload to bytes.
// func (payload *RelayCellPayload) Marshall() ([]byte, error) {
// 	buf := make([]byte, RelayHeaderSize+RelayPayloadSize)
// 	binary.BigEndian.PutUint16(buf[:2], payload.StreamID)
// 	copy(buf[2:2+DigestSize], payload.Digest[:])
// 	binary.BigEndian.PutUint16(buf[2+DigestSize:4+DigestSize], payload.Len)
// 	buf[4+DigestSize] = byte(payload.Cmd)
// 	copy(buf[RelayHeaderSize:], payload.Data[:])
// 	return buf, nil
// }

// Unmarshall deserializes the bytes into a RelayCellPayload.
func (payload *RelayCellPayload) Unmarshall(data []byte) error {
	if len(data) < RelayHeaderSize+RelayPayloadSize {
		return errors.New("incorrect number of bytes to unmarshall RelayCellPayload")
	}
	payload.StreamID = binary.BigEndian.Uint16(data[:2])
	copy(payload.Digest[:], data[2:2+DigestSize])
	payload.Len = binary.BigEndian.Uint16(data[2+DigestSize : 4+DigestSize])
	payload.Cmd = RelayCmdType(data[4+DigestSize])
	copy(payload.Data[:], data[RelayHeaderSize:])
	return nil
}

/************** RelayExtendCellPayload **************/

// Marshall converts ExtendCellPayload into bytes.
func (payload *RelayExtendCellPayload) Marshall() ([]byte, error) {
	// Marshal the PublicKey using x509
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(payload.PublicKey)
	if err != nil {
		return nil, err
	}
	// Marshal the netip.AddrPort
	addrPortBytes, err := payload.NextORAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Combine the command, public key, and AddrPort into one byte slice
	buf := new(bytes.Buffer)
	buf.Write(pubKeyBytes)
	buf.Write(addrPortBytes)
	return buf.Bytes(), nil
}

// Unmarshall parses bytes into an ExtendCellPayload.
func (payload *RelayExtendCellPayload) Unmarshall(data []byte) error {
	if len(data) < RelayPayloadSize {
		slog.Warn("Invalid relay cell data")
		return errors.New("Incorrect number of bytes recv")
	}

	pub, err := x509.ParsePKIXPublicKey(data[:MarshalledPublicKeySize])
	if err != nil {
		slog.Warn("Failed to unmarshall, from public key")
		return err
	}
	// Assert ecdsa public key and then call ECDH on it to get ecdh pub key
	payload.PublicKey, err = pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		if err != nil {
			slog.Warn("Failed to unmarshall, from public key")
			return err
		}
	}
	// Unmarshall the AddrPort
	// CHECK: 6 is for 9091, but it may not always be 6 bytes.
	err = payload.NextORAddr.UnmarshalBinary(data[MarshalledPublicKeySize : MarshalledPublicKeySize+6])
	if err != nil {
		return err
	}
	return nil
}

/************** RelayExtendedCellPayload **************/

// Marshall serializes the RelayExtendedCellPayload to bytes.
func (payload *RelayExtendedCellPayload) Marshall() ([]byte, error) {
	buf := new(bytes.Buffer)
	marshalledPubKey, err := x509.MarshalPKIXPublicKey(payload.PublicKey)
	if err != nil {
		slog.Warn("Failed to marshall.", "Err", err)
		return []byte{}, err
	}
	buf.Write(marshalledPubKey)
	buf.Write(payload.SharedSymKeyChecksum[:])
	return buf.Bytes(), nil
}

// Unmarshall deserializes the bytes into a RelayExtendedCellPayload.
func (payload *RelayExtendedCellPayload) Unmarshall(data []byte) error {
	pub, err := x509.ParsePKIXPublicKey(data[:MarshalledPublicKeySize])
	if err != nil {
		slog.Warn("Failed to unmarshall, from public key")
		return err
	}
	// Assert ecdsa public key and then call ECDH on it to get ecdh pub key
	payload.PublicKey, err = pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		if err != nil {
			slog.Warn("Failed to unmarshall, from public key")
			return err
		}
	}
	copy(payload.SharedSymKeyChecksum[:], data[MarshalledPublicKeySize:MarshalledPublicKeySize+SHA256ChecksumSize])
	return nil
}

/************** RelayDataCellPayload **************/
// Unmarshall takes a byte slice and stores it as a string in the struct.
func (payload *RelayDataCellPayload) Unmarshall(data []byte) error {
	if data == nil {
		return errors.New("data cannot be nil")
	}
	payload.Data = string(data)
	return nil
}

// Marshall returns the Data field as a byte slice.
func (payload *RelayDataCellPayload) Marshall() ([]byte, error) {
	if payload.Data == "" {
		return nil, errors.New("data is empty")
	}
	dataBytes := []byte(payload.Data)
	if len(dataBytes) > RelayPayloadSize {
		return nil, errors.New("exceed length limit")
	}

	return dataBytes, nil
}
