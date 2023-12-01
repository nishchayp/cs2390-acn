package common

import (
	"cs2390-acn/pkg/crypto"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
	"log/slog"
	"net"
	"net/netip"
)

// Send a create cell and get back a created cell, return the created cell payload
func CreateCellRT(circID uint16, createCellPayload *protocol.CreateCellPayload, nextHopAddr netip.AddrPort) (*protocol.CreatedCellPayload, error) {

	// Create a output socket and connect to entry OR
	conn, err := net.Dial("tcp4", nextHopAddr.String())
	if err != nil {
		slog.Warn("Failed to create a output socket and connect", "Err", err)
		return nil, err
	}

	marshalledPayload, err := createCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return nil, err
	}

	createCell := protocol.Cell{
		CircID: circID,
		Cmd:    uint8(protocol.Create),
	}
	copy(createCell.Data[:], marshalledPayload)

	err = createCell.Send(conn)
	if err != nil {
		slog.Warn("Failed to send cell", "Err", err)
		return nil, err
	}

	// Recv created cell as response
	createdCell := protocol.Cell{}
	err = createdCell.Recv(conn)
	if err != nil {
		slog.Warn("Failed to recv created cell", "Err", err)
		return nil, err
	}
	var createdCellPayload protocol.CreatedCellPayload
	err = createdCellPayload.Unmarshall(createdCell.Data[:])
	if err != nil {
		slog.Warn("Failed to unmarshall, Err", "Err", err)
		return nil, err
	}
	return &createdCellPayload, nil
}

// Send a relay cell and get back a realay cell, return the resp relay cell payload, always sent by OP
func RelayCellRT(circID uint16, relayCellPayload *protocol.RelayCellPayload, circuit *models.Circuit, destHopNum uint) (*protocol.RelayCellPayload, error) {

	// Create a output socket and connect to entry OR
	conn, err := net.Dial("tcp4", circuit.Path[0].AddrPort.String())
	if err != nil {
		slog.Warn("Failed to create a output socket and connect", "Err", err)
		return nil, err
	}
	defer conn.Close()

	marshalledPayload, err := relayCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return nil, err
	}

	relayCell := protocol.Cell{
		CircID: circID,
		Cmd:    uint8(protocol.Relay),
	}
	// Add peels to onion (encrypt)
	var encryptedMarshalledPayload [protocol.CellPayloadSize]byte
	copy(encryptedMarshalledPayload[:], marshalledPayload[:]) // This would mean payload followed by some 0s
	encryptedMarshalledPayload[protocol.CellPayloadSize-2] = byte(len(marshalledPayload) >> 8)
	encryptedMarshalledPayload[protocol.CellPayloadSize-1] = byte(len(marshalledPayload) & 0xFF)
	for i := int(destHopNum); i >= 0; i-- {
		encryptedMarshalledPayload, err = crypto.EncryptWrapper(encryptedMarshalledPayload, circuit.Path[i].SharedSymKey)
		if err != nil {
			slog.Warn("Failed to encrypt", "Peel (hop) num", i, "Err", err)
			return nil, err
		}
	}
	copy(relayCell.Data[:], encryptedMarshalledPayload[:])
	err = relayCell.Send(conn)
	if err != nil {
		slog.Warn("Failed to send relay cell", "Err", err)
		return nil, err
	}

	// Recv relay cell as response
	respRelayCell := protocol.Cell{}
	err = respRelayCell.Recv(conn)
	if err != nil {
		slog.Warn("Failed to recv resp relay cell", "Err", err)
		return nil, err
	}
	// Remove peels from onion (decrypt)
	decryptedMarshalledRespPayload := respRelayCell.Data
	for i := 0; i <= int(destHopNum); i++ {
		decryptedMarshalledRespPayload, err = crypto.DecryptWrapper(decryptedMarshalledRespPayload, circuit.Path[i].SharedSymKey)
		if err != nil {
			slog.Warn("Failed to encrypt", "Peel (hop) num", i, "Err", err)
			return nil, err
		}
	}
	var respRelayCellPayload protocol.RelayCellPayload
	err = respRelayCellPayload.Unmarshall(decryptedMarshalledRespPayload[:])
	if err != nil {
		slog.Warn("Failed to unmarshall, Err", "Err", err)
		return nil, err
	}

	return &respRelayCellPayload, nil
}

// Send a extend cell and get back a created cell, return the extended cell payload
func RelayCellExtendRT(circID uint16, relayExtendCellPayload *protocol.RelayExtendCellPayload, circuit *models.Circuit, destHopNum uint) (*protocol.RelayExtendedCellPayload, error) {

	marshalledPayload, err := relayExtendCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return nil, err
	}
	var dataToBeHashed [protocol.RelayPayloadSize]byte
	copy(dataToBeHashed[:], marshalledPayload[:])

	digest := crypto.HashDigest(dataToBeHashed[:])
	relayCellPayload := protocol.RelayCellPayload{
		StreamID: 0, // TODO: Set the StreamID if needed in the future
		Digest:   [protocol.DigestSize]byte(digest),
		Len:      uint16(len(marshalledPayload)),
		Cmd:      protocol.Extend,
	}
	copy(relayCellPayload.Data[:], marshalledPayload)

	respRelayCellPayload, err := RelayCellRT(circID, &relayCellPayload, circuit, destHopNum)
	if err != nil {
		slog.Warn("Failed to send recv relay cell", "Err", err)
		return nil, err
	}

	var relayExtendedCellPayload protocol.RelayExtendedCellPayload
	err = relayExtendedCellPayload.Unmarshall(respRelayCellPayload.Data[:])
	if err != nil {
		slog.Warn("Failed to unmarshall", "Err", err)
		return nil, err
	}

	return &relayExtendedCellPayload, nil
}

// Send a data cell and get back a data cell, return nil.
func RelayCellDataRT(circID uint16, relayDataCellPayload *protocol.RelayDataCellPayload, circuit *models.Circuit, destHopNum uint) (*protocol.RelayDataCellPayload, error) {

	// Marshall Data, construct and send the RelayDataCell
	marshalledPayload, err := relayDataCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall relayDataCell", "Err", err)
		return nil, err
	}
	var dataToBeHashed [protocol.RelayPayloadSize]byte
	copy(dataToBeHashed[:], marshalledPayload[:])

	digest := crypto.HashDigest(dataToBeHashed[:])
	relayCellPayload := protocol.RelayCellPayload{
		StreamID: 0, // TODO: Set the StreamID if needed in the future
		Digest:   [protocol.DigestSize]byte(digest),
		Len:      uint16(len(marshalledPayload)),
		Cmd:      protocol.Data,
	}
	copy(relayCellPayload.Data[:], marshalledPayload)

	// Receive respCell as RelayDataCell
	respRelayCellPayload, err := RelayCellRT(circID, &relayCellPayload, circuit, destHopNum)
	if err != nil {
		slog.Warn("Failed to send recv relay data cell from RelayCellRT", "Err", err)
		return nil, err
	}

	var relayRespDataCellPayload protocol.RelayDataCellPayload
	err = relayRespDataCellPayload.Unmarshall(respRelayCellPayload.Data[:respRelayCellPayload.Len])
	if err != nil {
		slog.Warn("Failed to unmarshall", "Err", err)
		return nil, err
	}
	// Print out the Data received from destination
	slog.Debug("Data Recd", "msg", relayRespDataCellPayload.Data)
	return &relayRespDataCellPayload, nil
}
