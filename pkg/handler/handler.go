package handler

import (
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
