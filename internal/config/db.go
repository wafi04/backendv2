package config

import (
	"database/sql"
	"fmt"
)

// Method ini pindah ke config package atau buat receiver yang benar
func NewSetupDatabase(dbConfig DatabaseConfig) (*sql.DB, error) {
	// Build connection string
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		dbConfig.User,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Database,
	)

	db, err := sql.Open(dbConfig.Driver, dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
