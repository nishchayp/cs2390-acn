package main

import (
	"cs2390-acn/pkg/oniondb"
	"log/slog"
	_ "github.com/mattn/go-sqlite3" // importing sqlite driver code
)


func main() {
	// Initialize the SQLite database
	db, err := oniondb.InitializeDB()
	if err != nil {
		slog.Error("Failed to initialize the database: ", err)
		return
	}
	defer db.Close()
}
