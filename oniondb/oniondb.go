package oniondb

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB // Database connection

func InitializeDB() (*sql.DB, error) {
	var err error // Initialize error variable
	db, err = sql.Open("sqlite3", "onion_router.db")
	/*if err != nil {
		return nil, err
	}*/

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

func AddDataToDB(id int, ip string, port int, publicKey string) error {
	onion_router_db, err := sql.Open("sqlite3", "onion_router.db")
	/*if err != nil {
		return nil, err
	}*/
	if onion_router_db == nil {
		return fmt.Errorf("Database connection is not initialized")
	}
	
	_, err = onion_router_db.Exec("REPLACE INTO onion_data (ID, IP, Port, PublicKey) VALUES (?, ?, ?, ?)", id, ip, port, publicKey)
	return err
}

func GetDataFromDB(id int) (string, int, string, error) {
	onion_router_db, err := sql.Open("sqlite3", "onion_router.db")

	if onion_router_db == nil {
		return "", 0, "", fmt.Errorf("Database connection is not initialized")
	}

	row := onion_router_db.QueryRow("SELECT IP, Port, PublicKey FROM onion_data WHERE ID = ?", id)
	var ip string
	var port int
	var publicKey string
	err = row.Scan(&ip, &port, &publicKey)
	if err != nil {
		return "", 0, "", err
	}

	return ip, port, publicKey, nil
}
