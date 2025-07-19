package internal

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool *pgxpool.Pool
}

func InitDB() (*DB, error) {
	url := os.Getenv("POSTGRES_URL")
	if url == "" {
		url = "postgresql://" + os.Getenv("POSTGRES_USER") + ":" + os.Getenv("POSTGRES_PASSWORD") + "@" + os.Getenv("POSTGRES_HOST") + ":" + os.Getenv("POSTGRES_PORT") + "/" + os.Getenv("POSTGRES_DB")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

func (db *DB) Close() {
	db.Pool.Close()
}

func (db *DB) InsertRequest(name, project, team, email, apiKey string) error {
	_, err := db.Pool.Exec(context.Background(),
		`INSERT INTO api_requests (name, project, team, email, api_key) VALUES ($1, $2, $3, $4, $5)`,
		name, project, team, email, apiKey,
	)
	return err
}

func (db *DB) GetProjectByAPIKey(apiKey string) (string, error) {
	row := db.Pool.QueryRow(context.Background(),
		`SELECT project FROM api_requests WHERE api_key=$1`, apiKey,
	)
	var project string
	if err := row.Scan(&project); err != nil {
		return "", err
	}
	return project, nil
}
