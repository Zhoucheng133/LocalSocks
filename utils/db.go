package utils

import (
	"database/sql"
	"os"

	_ "modernc.org/sqlite"
)

var db *sql.DB

const (
	dbDir      = "./db"
	dbFile     = "./db/database.db"
	initSchema = `
CREATE TABLE IF NOT EXISTS user (
	id       TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS server (
	id       TEXT PRIMARY KEY,
	name     TEXT NOT NULL,
	host     TEXT NOT NULL,
	username TEXT NOT NULL,
	password TEXT NOT NULL,
	running  INTEGER NOT NULL DEFAULT 0
);`
)

func InitDB() error {
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}

	d, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return err
	}

	if _, err := d.Exec(initSchema); err != nil {
		d.Close()
		return err
	}

	db = d
	return nil
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func countUsers() (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM user`).Scan(&count)
	return count, err
}
