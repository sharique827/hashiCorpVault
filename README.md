# HashiCorp Vault Key Management System

## Overview
This system consists of two Go microservices (`backend-service` and `kms-service`), PostgreSQL, Redis, and HashiCorp Vault, all orchestrated with Docker Compose.

- **backend-service**: Accepts user requests, generates API keys, stores in Postgres, optionally caches in Redis, and calls KMS for KEK generation.
- **kms-service**: Generates a KEK per project, stores it in Vault, and returns an ACK.

## Folder Structure
```
hashiCorpVault/
├── backend-service/
├── kms-service/
├── vault/
├── docker-compose.yml
└── README.md
```

## Setup
1. **Clone the repo**
2. **Configure environment variables** in `backend-service/.env` and `kms-service/.env` as needed.
3. **Start the system:**
   ```sh
   docker-compose up --build
   ```
4. **Initialize Vault (first time only):**
   ```sh
   docker exec -it <vault_container_id> vault operator init
   docker exec -it <vault_container_id> vault operator unseal
   # Save the unseal keys and root token securely!
   ```
5. **Access services:**
   - Backend: http://localhost:8080
   - KMS: http://localhost:8081
   - Vault UI: http://localhost:8200
   - Postgres: localhost:5432
   - Redis: localhost:6379

## Notes
- Vault data is persisted in `vault/file/`.
- Postgres data is persisted in the `pgdata` Docker volume.
- Update `.env` files with your secrets in production.
