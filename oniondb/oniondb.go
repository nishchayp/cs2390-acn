package oniondb

import (
	"fmt"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB // Database connection

func InitializeDB() (*sql.DB, error) {
	var err error // Initialize error variable
	db, err = sql.Open("sqlite3", "onion_router.db")
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

func AddDataToDB(ip string, port int, publicKey string) error {
	if db == nil {
		return fmt.Errorf("Database connection is not initialized")
	}
	_, err := db.Exec("INSERT INTO onion_data (IP, Port, PublicKey) VALUES (?, ?, ?)", ip, port, publicKey)
	return err
}
