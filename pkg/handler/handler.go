package handler

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"cs2390-acn/pkg/crypto"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
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
	self.CircuitLinkMap[createCell.CircID] = models.CircuitLink{
		SharedSymKey: sharedSymKey,
	}

	// Return created cell
	createdPayload := protocol.CreatedCellPayload{
		PublicKey:            sessionPubKey,
		SharedSymKeyChecksum: crypto.Hash(sharedSymKey),
	}
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

	// relayCell.CircID = circuitLink.NextCircID

	// Decrypt the cell payload with the shared secret.
	decryptedPayload, err := crypto.DecryptData(circuitLink.SharedSymKey, relayCell.Data[:])
	if err != nil {
		slog.Error("Failed to decrypt relay cell payload", "Err", err)
		return
	}

	// Parse the decrypted payload into a RelayCellPayload structure.
	var relayPayload protocol.RelayCellPayload
	err = relayPayload.Unmarshall(decryptedPayload)
	if err != nil {
		slog.Warn("Failed to unmarshal relay cell payload", "Err", err)
		return
	}
	hashedData := crypto.HashDigest(relayPayload.Data[:])

	// if digest != hash(data), forward the original cell with only CircID changed
	if !bytes.Equal(hashedData[:], relayPayload.Digest[:]) {
		// CHECK: how it make sure which one to forward? Since it does not include destination's IP addr for now.
		// Check in map that for the curr ckt link what is the next ckt link
		// next ckt link will have the next circ id -> use this to send forward
		// next ckt link will have the next addr -> use this to create connection and then send cell
		// relayCell.Send(new_conn)
		return
	}

	// else, handle per cmd
	switch relayPayload.Cmd {
	case protocol.Extend:
		handleExtendCommand(self, conn, &relayPayload, relayCell.CircID)
	case protocol.Data:
		// CHECK: handleProcessData(): We just print it for now?
	default:
		slog.Warn("Unknown relay command", "Command", relayPayload.Cmd)
	}
}

// Handles the EXTEND command for the relay cell.

func handleExtendCommand(self *models.OnionRouter, conn net.Conn, relayPayload *protocol.RelayCellPayload, circID uint16) {
	marshalledPubKey := relayPayload.Data[:crypto.PubKeyByteSize]
	marshalledExtendPayload := relayPayload.Data[crypto.PubKeyByteSize:relayPayload.Len]
	// Unmarshal relayPayload
	sessionPubKey, err := x509.ParsePKIXPublicKey(marshalledPubKey)
	if err != nil {
		slog.Error("Failed to unmarshal public key", "Err", err)
		return
	}
	extendCellPayload, err := protocol.UnmarshallExtendCellPayload(marshalledExtendPayload)
	if err != nil {
		slog.Error("Failed to unmarshal marshalledExtendPayload", "Err", err)
		return
	}

	// Parse the Extend payload for next OR and encrypted data.
	sessionPrivKey, sessionPubKey, err := crypto.GenerateKeyPair(self.Curve)
	if err != nil {
		slog.Warn("Failed to generate session key pair", "Err", err)
		return
	}

	actualPubKey, ok := sessionPubKey.(*ecdh.PublicKey)
	if !ok {
		slog.Error("sessionPubKey is not of type *ecdh.PublicKey")
		return
	}
	createCellPayload := protocol.CreateCellPayload{
		PublicKey: actualPubKey,
	}
	marshalledPayload, err := createCellPayload.Marshall()
	if err != nil {
		slog.Warn("Failed to establish ckt.", "Err", err)
		return
	}

	createCell := protocol.Cell{
		CircID: circID,
		Cmd:    uint8(protocol.Create),
	}

	// Create a output socket and connect to OR2
	newConn, err := net.Dial("tcp4", extendCellPayload.NextORAddr.String())
	if err != nil {
		slog.Warn("Failed to create a output socket and connect to OR2", "Err", err)
		return
	}
	copy(createCell.Data[:], marshalledPayload)

	createCell.Send(newConn)

	// Listen for the created cell response from OR2.
	createdCell := protocol.Cell{}
	err = createdCell.Recv(newConn)
	if err != nil {
		slog.Error("Failed to receive created cell from the next Onion Router", "Err", err)
		return
	}

	// Prepare the Extended payload.
	extendedPayload 
	extendedCell := protocol.Cell{
		CircID: 1,
		Cmd:    uint8(protocol.Extended),
		Data:  
	}
	// Send the extended payload back to the original connection (OP).
	extendedCell.Send(conn)
}
