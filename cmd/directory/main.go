package main

import (
	"database/sql"
	"cs2390-acn/oniondb"
	"log/slog"
	_ "github.com/mattn/go-sqlite3" // importing sqlite driver code
)

var DB *sql.DB

func main() {
	// Initialize the SQLite database
	DB, err := oniondb.InitializeDB()
	if err != nil {
		slog.Error("Failed to initialize the database: ", err)
		return
	}
	defer DB.Close()
}
