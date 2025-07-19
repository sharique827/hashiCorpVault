package internal

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type InvoiceDB struct {
	Pool *pgxpool.Pool
}

type InvoiceRecord struct {
	ID         int
	Project    string
	InvoiceID  string
	EDEK       []byte
	Encrypted  []byte
	KeyVersion string
	DEKNonce   []byte
	DataNonce  []byte
	CreatedAt  string
}

func (db *InvoiceDB) InsertInvoice(project, invoiceID string, edek, encrypted, dekNonce, dataNonce []byte, keyVersion string) error {
	_, err := db.Pool.Exec(context.Background(),
		`INSERT INTO invoice (project, invoice_id, edek, encrypted_data, dek_nonce, data_nonce, key_version) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		project, invoiceID, edek, encrypted, dekNonce, dataNonce, keyVersion,
	)
	return err
}

func (db *InvoiceDB) GetInvoice(project, invoiceID string) (*InvoiceRecord, error) {
	row := db.Pool.QueryRow(context.Background(),
		`SELECT id, project, invoice_id, edek, encrypted_data, key_version, dek_nonce, data_nonce, created_at FROM invoice WHERE project=$1 AND invoice_id=$2`,
		project, invoiceID,
	)
	rec := &InvoiceRecord{}
	err := row.Scan(&rec.ID, &rec.Project, &rec.InvoiceID, &rec.EDEK, &rec.Encrypted, &rec.KeyVersion, &rec.DEKNonce, &rec.DataNonce, &rec.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rec, nil
}
