package protocol

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
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
)

type CmdType uint8

const (
	Relay   CmdType = 0
	Create  CmdType = 1
	Created CmdType = 2
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
	PublicKey *ecdh.PublicKey
}

type CreatedCellPayload struct {
	PublicKey            *ecdh.PublicKey
	SharedSymKeyChecksum [SHA256ChecksumSize]byte
}

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

// Marshall serializes the CreatedCellPayload to bytes.
func (payload *CreatedCellPayload) Marshall() ([]byte, error) {
	buf := make([]byte, CellPayloadSize)
	marshalledPubKey, err := x509.MarshalPKIXPublicKey(payload.PublicKey)
	slog.Debug("Debug", "Marshalled key sz", len(marshalledPubKey))
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