package oniondb

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"cs2390-acn/pkg/models"
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

	_, err = onion_router_db.Exec("REPLACE INTO onion_data (ID, IP, Port, PublicKey) VALUES (?, ?, ?, ?)",
		entry.ID, entry.IP, entry.Port, entry.PublicKey)
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

	row := onion_router_db.QueryRow("SELECT IP, Port, PublicKey FROM onion_data WHERE ID = ?", id)
	var entry models.DirectoryEntry
	err = row.Scan(&entry.IP, &entry.Port, &entry.PublicKey)
	if err != nil {
		return models.DirectoryEntry{}, err
	}

	entry.ID = id // Set the ID in the returned entry
	return entry, nil
}
