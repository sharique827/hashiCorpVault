# HashiCorp Vault Envelope Encryption System (Vault Transit Edition)

## Overview

This project uses HashiCorp Vault's Transit Secrets Engine for maximum security. All cryptographic operations (wrapping/unwrapping DEKs) are performed by Vault. The KEK never leaves Vault memory.

---

## Architecture & Encryption Flow

```mermaid
flowchart TD
    A["Client"]
    B["Backend Service"]
    D["HashiCorp Vault (Transit)"]
    E["PostgreSQL"]
    F["Redis (optional)"]

    A -- "Register Project/Request API Key" --> B
    B -- "Generate API Key, Store in DB/Redis" --> E
    B -- "Create Transit Key for Project" --> D
    B -- "Return API Key" --> A

    A -- "Create Invoice (plaintext)" --> B
    B -- "Generate DEK, Encrypt Data" --> B
    B -- "Request EDEK: Send DEK to Vault Transit /encrypt" --> D
    D -- "Return EDEK to Backend" --> B
    B -- "Store EDEK + Encrypted Data" --> E

    A -- "Fetch Invoice" --> B
    B -- "Fetch EDEK + Encrypted Data" --> E
    B -- "Request DEK: Send EDEK to Vault Transit /decrypt" --> D
    D -- "Return DEK to Backend" --> B
    B -- "Decrypt Data with DEK" --> B
    B -- "Return Plaintext Invoice" --> A
```

---

## Registration (Project/KEK Creation)
- Backend calls:
  - `POST /v1/transit/keys/<project>-kek` (type: aes256-gcm96)
- Vault creates and manages the KEK internally.

## Invoice Creation (Envelope Encryption)
- Backend generates DEK, encrypts invoice data.
- Backend calls:
  - `POST /v1/transit/encrypt/<project>-kek` with `{ "plaintext": "<base64 DEK>" }`
- Vault returns `{ "ciphertext": "vault:v1:..." }` (EDEK).
- Backend stores encrypted data + EDEK in Postgres.

## Invoice Fetch (Envelope Decryption)
- Backend fetches encrypted data + EDEK from Postgres.
- Backend calls:
  - `POST /v1/transit/decrypt/<project>-kek` with `{ "ciphertext": "<EDEK>" }`
- Vault returns `{ "plaintext": "<base64 DEK>" }`.
- Backend decrypts invoice data with the DEK.

---

## Folder Structure

```
hashiCorpVault/
├── backend-service/
│   ├── main.go
│   ├── internal/
│   │   ├── db.go
│   │   ├── cache.go
│   │   ├── handler.go
│   │   ├── kms_client.go
│   │   ├── encryption.go
│   │   ├── invoice_db.go
│   │   └── invoice_handler.go
│   ├── Dockerfile
│   ├── go.mod
│   └── .env.example
├── kms-service/
│   ├── main.go
│   ├── internal/
│   │   ├── vault.go
│   │   └── handler.go
│   ├── Dockerfile
│   ├── go.mod
│   └── .env.example
├── vault/
│   ├── config.hcl
│   └── file/
├── docker-compose.yml
└── README.md
```

---

**You can copy and paste this into your `README.md`.**  
If you want a PNG or SVG diagram, let me know and I can generate/export one for you!  
Let me know if you want to customize any section or add more details.

---

## Step-by-Step Setup

### 1. **Clone the Repository**
```bash
git clone <your-repo-url>
cd hashiCorpVault
```

### 2. **Configure Environment Variables**
- Copy `.env.example` to `.env` in both `backend-service/` and `kms-service/` and fill in secrets as needed.

### 3. **Start All Services**
```bash
docker-compose up --build -d
```

### 4. **Initialize and Unseal Vault**
```bash
docker exec -it hashicorpvault-vault-1 vault operator init
# Save the unseal keys and root token!
docker exec -it hashicorpvault-vault-1 vault operator unseal <unseal_key_1>
docker exec -it hashicorpvault-vault-1 vault operator unseal <unseal_key_2>
docker exec -it hashicorpvault-vault-1 vault operator unseal <unseal_key_3>
```

### 5. **Create Database Tables**
```bash
docker exec -it hashicorpvault-postgres-1 psql -U backend_user -d backend_db
```
Then in the psql prompt:
```sql
CREATE TABLE api_requests (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    project TEXT NOT NULL,
    team TEXT NOT NULL,
    email TEXT NOT NULL,
    api_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE invoice (
    id SERIAL PRIMARY KEY,
    project TEXT NOT NULL,
    invoice_id TEXT NOT NULL,
    edek BYTEA NOT NULL,
    encrypted_data BYTEA NOT NULL,
    dek_nonce BYTEA NOT NULL,
    data_nonce BYTEA NOT NULL,
    key_version TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
Type `\q` to exit.

### 6. **(Optional) Manually Add a KEK for Testing**
If KMS is not running or you want to test quickly:
```bash
docker exec -it hashicorpvault-vault-1 sh
vault login <root_token>
vault kv put secret/project1 kek=$(openssl rand -base64 32)
```

---

## API Endpoints

### **Register Project / Get API Key**
```http
POST /register
Content-Type: application/json

{
  "name": "Alice",
  "project": "project1",
  "team": "devops",
  "email": "alice@example.com"
}
```
**Response:**
```json
{ "api_key": "..." }
```

---

### **Create Invoice (Encrypt)**
```http
POST /invoice/create
Content-Type: application/json

{
  "project": "project1",
  "invoice_id": "inv001",
  "data": "Sensitive invoice data"
}
```
**Response:**
```json
{ "invoice_id": "inv001", "status": "stored" }
```

---

### **Fetch Invoice (Decrypt)**
```http
POST /invoice/fetch
Content-Type: application/json

{
  "project": "project1",
  "invoice_id": "inv001"
}
```
**Response:**
```json
{ "invoice_id": "inv001", "data": "Sensitive invoice data" }
```

---

### **KMS Service: Generate KEK**
```http
POST /generate-kek
Content-Type: application/json

{ "project": "project1" }
```
**Response:**
```json
{ "status": "ACK" }
```

---

## Security Best Practices

- **KEKs are never exposed to or handled by the backend.**
- **All KEK operations (wrap/unwrap) are performed inside KMS/Vault.**
- **DEKs are zeroed from memory after use.**
- **All encryption uses AES-GCM (authenticated encryption).**
- **Key versioning is supported for future rotation.**
- **.env files are not committed to git.**
- **Use HTTPS in production.**
- **Vault and Postgres data are persisted via Docker volumes.**

---

## Troubleshooting

- If Vault is not running, endpoints that require KEK will fail.
- If you get `Failed to fetch KEK`, check Vault logs and ensure the KEK exists for the project.
- Use `docker logs <container>` to debug services.

---

## License

MIT

---

## Authors

<!-- - [Your Name](https://github.com/yourusername) -->




