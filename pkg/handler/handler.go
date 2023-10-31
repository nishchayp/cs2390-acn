package handler

import (
	"cs2390-acn/pkg/protocol"
	"log/slog"
	"net"
)

type CellHandlerFunc = func(net.Conn, *protocol.Cell)

func CreateCellHandler(conn net.Conn, cell *protocol.Cell) {
	slog.Info("Recv cell: %+v", cell)
}
