package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Initialize the SQLite database
func InitializeDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "onion_router.db")
	if err != nil {
		return nil, err
	}

	// Create the 'onion_data' table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS onion_data (
			ID INTEGER PRIMARY KEY,
			IP TEXT,
			Port INTEGER,
			PublicKey TEXT
		)`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func AddDataToDB(db *sql.DB, ip string, port int, publicKey string) error {
	_, err := db.Exec("INSERT INTO onion_data (IP, Port, PublicKey) VALUES (?, ?, ?)", ip, port, publicKey)
	return err
}

func main() {
	// Initialize the SQLite database
	db, err := InitializeDB()
	if err != nil {
		log.Fatalf("Failed to initialize the database: %v", err)
	}
	defer db.Close()
}
