package handler

import (
	"bytes"
	"cs2390-acn/pkg/common"
	"cs2390-acn/pkg/crypto"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

// Recieves create cell, sends its share and creates shared secret
func CreateCellHandler(self *models.OnionRouter, conn net.Conn, createCell *protocol.Cell) {
	slog.Debug("Recv in handler", "createCell", createCell)
	var createPayload protocol.CreateCellPayload
	err := createPayload.Unmarshall(createCell.Data[:])
	if err != nil {
		slog.Warn("Failed to unmarshall, Err", "Err", err)
		return
	}
	slog.Debug("Public key", "key", createPayload.PublicKey.Bytes())

	// Create the shared secret
	// Generate session key pair
	sessionPrivKey, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
	if err != nil {
		slog.Warn("Failed to generate session key pair", "Err", err)
		return
	}
	sharedSymKey, err := crypto.ComputeSharedSecret(sessionPrivKey, createPayload.PublicKey)
	if err != nil {
		slog.Error("Failed to compute shared secret", "Err", err)
		return
	}
	_, exists := self.CircuitLinkMap[createCell.CircID]
	if exists {
		slog.Warn("Circuit link already present.", "CircID", createCell.CircID)
		return
	}
	self.CircuitLinkMap[createCell.CircID] = models.CircuitLink{
		SharedSymKey: sharedSymKey,
		NextCircID:   protocol.InvalidCircId, // this is terminal and does not have a next link
	}

	// Return created cell
	createdPayload := protocol.CreatedCellPayload{
		PublicKey:            sessionPubKey,
		SharedSymKeyChecksum: crypto.Hash(sharedSymKey),
	}

	// Debug info
	intSlice := make([]int, len(sharedSymKey))
	for i, b := range sharedSymKey {
		intSlice[i] = int(b)
	}
	slog.Debug("shared sharedSymKey", "local sharedSymKey", intSlice)
	slog.Debug("shared secrets checksum", "local checksum", crypto.Hash(sharedSymKey))
	slog.Debug("shared secret", "local", sharedSymKey)

	marshalledCreatedPayload, err := createdPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return
	}
	createdCell := protocol.Cell{
		CircID: createCell.CircID,
		Cmd:    uint8(protocol.Created),
	}
	copy(createdCell.Data[:], marshalledCreatedPayload[:])

	createdCell.Send(conn)

	slog.Info("Established Circuit link")
}

// Recieves relay cell
// 1. Check the circuit id, change the cell.circid to nextcircid
// 2. Decrypts with its shared secret
// 3. Parse the decrypted payload into a RelayCellPayload structure
// 4. Check if digest == data, if so, get cmd; else, forward
func RelayCellHandler(self *models.OnionRouter, conn net.Conn, relayCell *protocol.Cell) {
	slog.Debug("Received relay cell in handler", "relayCell", relayCell)

	circuitLink, exists := self.CircuitLinkMap[relayCell.CircID]
	if !exists {
		slog.Warn("Circuit not found for relay cell", "CircID", relayCell.CircID)
		return
	}

	// Remove a onion peel since it is a relay cell
	// Decrypt the cell payload with the shared secret.
	slog.Debug("[OR] Before encryption: ", "relayCell.Data", relayCell.Data)
	decryptedPayload, err := crypto.DecryptWrapper(relayCell.Data, circuitLink.SharedSymKey)
	if err != nil {
		slog.Error("Failed to decrypt relay cell payload", "Err", err)
		return
	}
	// Parse the decrypted payload into a RelayCellPayload structure.
	var relayPayload protocol.RelayCellPayload
	err = relayPayload.Unmarshall(decryptedPayload[:])
	slog.Debug("[OR] After encryption and Unmarshall: ", "relayCell Payload", decryptedPayload)
	if err != nil {
		slog.Warn("Failed to unmarshal relay cell payload", "Err", err)
		return
	}
	respRelayCell := protocol.Cell{
		CircID: relayCell.CircID,
		Cmd:    uint8(protocol.Relay),
	}

	var dataToBeHashed [protocol.RelayPayloadSize]byte
	copy(dataToBeHashed[:], relayPayload.Data[:protocol.RelayPayloadSize-2])

	hashedData := crypto.HashDigest(dataToBeHashed[:])
	slog.Info("[OR1 digest]", "\nrelayPayload.data: ", dataToBeHashed, "\n hashedData: ", hashedData)
	slog.Debug("[Compare]", "hashedData:", hashedData, "Digest", relayPayload.Digest)
	// Handle according to the relay cell payload
	// if digest != hash(data), you are just a transit, forward the cell with a peel removed (decrypted) and CircID changed
	if !bytes.Equal(hashedData[:], relayPayload.Digest[:]) {
		slog.Debug("RelayCellForward", "Self:", self, "CircID", relayCell.CircID, "Payload:", &relayPayload)
		var marshalledRespRelayPayload [protocol.CellPayloadSize]byte
		marshalledRespRelayPayload, err = RelayCellForwardHandler(self, relayCell.CircID, decryptedPayload)
		if err != nil {
			slog.Warn("Failed to forward relay cell")
			return
		}
		encryptedPayload, err := crypto.EncryptWrapper(marshalledRespRelayPayload, circuitLink.SharedSymKey)
		if err != nil {
			slog.Error("Failed to decrypt relay cell payload", "Err", err)
			return
		}
		copy(respRelayCell.Data[:], encryptedPayload[:])
	} else { // The relay cell is meant for this OR, handle it appropriately
		relayCellHandlerFunc, ok := self.RelayCellHandlerRegistry[relayPayload.Cmd]
		if !ok {
			slog.Warn("Dropping relay cell", "unsuported relay cell cmd", relayPayload.Cmd)
			return
		}
		var marshalledRespRelayPayload []byte
		marshalledRespRelayPayload, err = relayCellHandlerFunc(self, relayCell.CircID, &relayPayload)
		if err != nil {
			slog.Warn("Failed to handle relay cell")
			return
		}
		// Respond back to the conn with respose received from further along the circuit
		// Encrypt again and change the circ id back to original

		// Add back a onion peel since it is a relay cell
		// Encrypt the cell payload with the shared secret.
		// Add ISO 10126-2 padding before encrypt.
		var temp [protocol.CellPayloadSize]byte
		payloadLength := len(marshalledRespRelayPayload)
		slog.Debug("Payload", "Len:", payloadLength, "marshalled", marshalledRespRelayPayload, "RespRelay:", respRelayCell, "size", protocol.CellPayloadSize)

		if payloadLength > protocol.CellPayloadSize-1 {
			slog.Error("Payload exceeds maximum length!", "Err", err)
			return
		}

		// Set the last two bytes of temp
		temp[protocol.CellPayloadSize-2] = byte(payloadLength >> 8)
		temp[protocol.CellPayloadSize-1] = byte(payloadLength & 0xFF)

		copy(temp[:], marshalledRespRelayPayload)
		// Encrypt on the temp array
		encryptedPayload, err := crypto.EncryptWrapper(temp, circuitLink.SharedSymKey)
		if err != nil {
			slog.Error("Failed to decrypt relay cell payload", "Err", err)
			return
		}
		copy(respRelayCell.Data[:], encryptedPayload[:])
	}

	respRelayCell.Send(conn)
	return
}

// Peel and forward a cell and then get the response and add peel and send it back
// CHECK: we should directly use decrypted(from OR1) cell payload as the Data field for forwardRelayCell
func RelayCellForwardHandler(self *models.OnionRouter, circID uint16, marshalledData [protocol.CellPayloadSize]byte) ([protocol.CellPayloadSize]byte, error) {
	circuitLink, exists := self.CircuitLinkMap[circID]
	if !exists {
		slog.Warn("Circuit not found for relay cell", "CircID", circID)
		return [protocol.CellPayloadSize]byte{}, errors.New("circuit not found for relay cell")
	}
	slog.Debug("CircuitLink Relay", "NextCircID", circuitLink.NextCircID, "CircLink", self.CircuitLinkMap[circID], "CircID", circID)

	if circuitLink.NextCircID == protocol.InvalidCircId { // Does not have a link to forward, it's the last link
		slog.Warn("No next link to forward to")
		return [protocol.CellPayloadSize]byte{}, errors.New("no next link to forward to")
	}
	forwardRelayCell := protocol.Cell{
		CircID: circuitLink.NextCircID,
		Cmd:    uint8(protocol.Relay),
	}
	copy(forwardRelayCell.Data[:], marshalledData[:])

	// Create a output socket and connect to entry OR
	forwarderConn, err := net.Dial("tcp4", circuitLink.NextORAddrPort.String())
	if err != nil {
		slog.Warn("Failed to create a output socket and connect", "Err", err)
		return [protocol.CellPayloadSize]byte{}, err
	}
	defer forwarderConn.Close()
	err = forwardRelayCell.Send(forwarderConn)
	if err != nil {
		slog.Warn("Failed to forward", "Err", err)
		return [protocol.CellPayloadSize]byte{}, err
	}

	// Recv on this forwardConn the response
	respRelayCell := protocol.Cell{}
	err = respRelayCell.Recv(forwarderConn)
	if err != nil {
		slog.Warn("Failed to forward", "Err", err)
		return [protocol.CellPayloadSize]byte{}, err
	}
	return respRelayCell.Data, nil
}

// Handle relay extend by sending a create cell to the required OR and getting back the reponse of the partial handshake and
// returning it back to where you got the relay cell from
func RelayCellExtendHandler(self *models.OnionRouter, circID uint16, relayPayload *protocol.RelayCellPayload) ([]byte, error) {
	circuitLink, exists := self.CircuitLinkMap[circID]
	if !exists {
		slog.Warn("Circuit not found for relay cell", "CircID", circID)
		return []byte{}, errors.New("circuit not found for relay cell")
	}

	relayExtendCellPayload := protocol.RelayExtendCellPayload{}
	err := relayExtendCellPayload.Unmarshall(relayPayload.Data[:])
	if err != nil {
		slog.Warn("Failed to unmarshall", "Err", err)
		return []byte{}, err
	}

	// Make a create cell out of this relay extend cell and send it to establish shared secret b/w
	// the sender of the relay extend cmd (original sender) and the next hop
	createCellPayload := protocol.CreateCellPayload{
		PublicKey: relayExtendCellPayload.PublicKey,
	}
	createdCellPayload, err := common.CreateCellRT(self.CircIDCounter, &createCellPayload, relayExtendCellPayload.NextORAddr)
	if err != nil {
		slog.Warn("Failed to establish circuit", "Hop", 0, "Err", err)
	}
	// update map and circid counter since success
	circuitLink.NextCircID = self.CircIDCounter
	circuitLink.NextORAddrPort = relayExtendCellPayload.NextORAddr
	self.CircuitLinkMap[circID] = circuitLink
	self.CircIDCounter++
	slog.Info("after received CreatedCell: ", "CircuitLinkMap", self.CircuitLinkMap, "CircIDCounter", self.CircIDCounter)
	slog.Info("CreatedCell: ", "Content", createdCellPayload)
	slog.Info("[Extend sharedSymKey]!!!!", "createdCellPayload.SharedSymKeyChecksum", createdCellPayload.SharedSymKeyChecksum)
	// From the response create a relay extended cell
	relayExtendedCellPayload := protocol.RelayExtendedCellPayload{
		PublicKey:            createdCellPayload.PublicKey,
		SharedSymKeyChecksum: createdCellPayload.SharedSymKeyChecksum,
	}

	marshalledRelayExtendedCellPayload, err := relayExtendedCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return []byte{}, err
	}
	var dataToBeHashed [protocol.RelayPayloadSize]byte
	copy(dataToBeHashed[:], marshalledRelayExtendedCellPayload[:])

	digest := crypto.HashDigest(dataToBeHashed[:])

	respRelayCellPayload := protocol.RelayCellPayload{
		StreamID: 0, // TODO: Set the StreamID if needed in the future
		Digest:   [protocol.DigestSize]byte(digest),
		Len:      uint16(len(marshalledRelayExtendedCellPayload)),
		Cmd:      protocol.Extend,
	}
	copy(respRelayCellPayload.Data[:], marshalledRelayExtendedCellPayload)

	marshalledRespRelayCellPayload, err := respRelayCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return []byte{}, err
	}

	return marshalledRespRelayCellPayload, nil
}

func RelayCellDataHandler(self *models.OnionRouter, circID uint16, relayPayload *protocol.RelayCellPayload) ([]byte, error) {

	// error check
	_, exists := self.CircuitLinkMap[circID]
	if !exists {
		slog.Warn("Circuit not found for relay cell", "CircID", circID)
		return []byte{}, errors.New("circuit not found for relay cell")
	}

	// Unmarshall Data and Process it (print it in terminal)
	relayDataCellPayload := protocol.RelayDataCellPayload{}
	err := relayDataCellPayload.Unmarshall(relayPayload.Data[:relayPayload.Len])
	if err != nil {
		slog.Warn("Failed to unmarshall", "Err", err)
		return []byte{}, err
	}
	printedData := relayDataCellPayload.Data
	fmt.Printf("Data Reiceived: %s\n", printedData)

	// From the response create a relay data resp cell
	relayDataRespCellPayload := protocol.RelayDataCellPayload{
		Data: printedData,
	}

	marshalledRelayDataCellPayload, err := relayDataRespCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall relayDataRespCellPayload", "Err", err)
		return []byte{}, err
	}
	var dataToBeHashed [protocol.RelayPayloadSize]byte
	copy(dataToBeHashed[:], marshalledRelayDataCellPayload[:])

	digest := crypto.HashDigest(dataToBeHashed[:])

	respRelayCellPayload := protocol.RelayCellPayload{
		StreamID: 0,
		Digest:   [protocol.DigestSize]byte(digest),
		Len:      uint16(len(marshalledRelayDataCellPayload)),
		Cmd:      protocol.Data,
	}
	copy(respRelayCellPayload.Data[:], marshalledRelayDataCellPayload)

	marshalledRespRelayCellPayload, err := respRelayCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to marshall", "Err", err)
		return []byte{}, err
	}

	return marshalledRespRelayCellPayload, nil
}
