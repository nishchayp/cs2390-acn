package oniondb

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"cs2390-acn/pkg/models"
	"cs2390-acn/pkg/protocol"
)

var db *sql.DB // Database connection

func InitializeDB() (*sql.DB, error) {
	var err error
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

// AddDataToDB function with DirectoryEntry struct
func AddDataToDB(entry models.DirectoryEntry) error {
	// Open the database connection
	onion_router_db, err := sql.Open("sqlite3", "onion_router.db")
	if err != nil {
		return err
	}
	defer onion_router_db.Close()

	// Convert the DirectoryEntry's PublicKey to a string using protocol.MarshalPublicKey
	publicKeyString, err := protocol.MarshalPublicKey(entry.PublicKey)
	if err != nil {
		return err
	}

	_, err = onion_router_db.Exec("REPLACE INTO onion_data (ID, IP, Port, PublicKey) VALUES (?, ?, ?, ?)",
		entry.ID, entry.IP.String(), entry.Port, publicKeyString)
	return err
}

// GetDataFromDB function with DirectoryEntry struct
func GetDataFromDB(id int) (models.DirectoryEntry, error) {
	// Open the database connection
	onion_router_db, err := sql.Open("sqlite3", "onion_router.db")
	if err != nil {
		return models.DirectoryEntry{}, err
	}
	defer onion_router_db.Close()

	row := onion_router_db.QueryRow("SELECT ID, IP, Port, PublicKey FROM onion_data WHERE ID = ?", id)
	var entry models.DirectoryEntry
	var publicKeyString string
	err = row.Scan(&entry.ID, &entry.IP, &entry.Port, &publicKeyString)
	if err != nil {
		return models.DirectoryEntry{}, err
	}

	// Convert the stored PublicKey string back to a PublicKey using protocol.UnmarshalPublicKey
	publicKey, err := protocol.UnmarshalPublicKey(publicKeyString)
	if err != nil {
		return models.DirectoryEntry{}, err
	}

	entry.PublicKey = publicKey
	return entry, nil
}
