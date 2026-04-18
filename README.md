# ACME Server (C++)

This repository contains a production-oriented C++20 scaffold for an ACME server that can support multiple downstream certificate authorities. The first CA adapter targets EJBCA Community Edition using its REST enrollment APIs.

## What is included

- ACME application services for `newNonce` and `newAccount`
- Socket-based HTTP transport for `directory`, `newNonce`, `newAccount`, `newOrder`, `authz`, `challenge`, `finalize`, and certificate download
- RFC 8555 style External Account Binding verification using server-side mappings
- ACME JWS envelope parsing with `protected` / `payload` / `signature`, `nonce`, `url`, `jwk`, and `kid`
- Extensible CA abstraction for public or private CA backends
- First EJBCA Community Edition adapter targeting `certificate/pkcs10enroll`
- File-backed repositories and PostgreSQL-backed repositories for ACME state
- Simple demo executable and lightweight tests

## EAB mapping model

The server-side EAB mapping table is modeled with these columns:

- `id`
- `client_id`
- `hmac_key`
- `ca`
- `credentials_id`

`client_id` is used as the RFC 8555 `kid` for EAB verification.

## Build

```bash
make
```

## Run server

```bash
./acme_server_demo
```

The server loads [`config/server.conf`](/Users/ayushaher/Projects/ACME%20Server/config/server.conf) and seeds mappings from [`data/eab_mappings.csv`](/Users/ayushaher/Projects/ACME%20Server/data/eab_mappings.csv).

## Endpoints

- `GET /healthz`
- `GET /acme/directory`
- `HEAD /acme/newNonce`
- `GET /acme/newNonce`
- `POST /acme/newAccount`
- `POST /acme/newOrder`
- `POST /acme/acct/<account-id>`
- `POST /acme/order/<order-id>`
- `POST /acme/order/<order-id>/finalize`
- `POST /acme/authz/<authorization-id>`
- `POST /acme/challenge/<challenge-id>`
- `POST /acme/certificate/<certificate-id>`

## Example `newAccount` request

The transport now expects an ACME JWS envelope (`application/jose+json`) for POST requests:

```json
{
  "protected": "<base64url protected header>",
  "payload": "<base64url payload>",
  "signature": "<base64url signature>"
}
```

For `finalize`, the payload uses the standard ACME `csr` field encoded as base64url DER. The server converts that CSR into PEM before handing it to the OpenSSL issuer.

## PostgreSQL

Set `storage_backend=postgres` in [`config/server.conf`](/Users/ayushaher/Projects/ACME%20Server/config/server.conf) and point `postgres_connection_string` at your database. On startup, the server applies [`sql/postgres_schema.sql`](/Users/ayushaher/Projects/ACME%20Server/sql/postgres_schema.sql) and seeds `eab_mappings` from [`data/eab_mappings.csv`](/Users/ayushaher/Projects/ACME%20Server/data/eab_mappings.csv).

## Run tests

```bash
make test
```

## EJBCA integration notes

The adapter is aligned with the EJBCA Community REST enrollment flow documented by Keyfactor for:

- `POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll`

The implementation uses a transport abstraction. The included `ShellHttpClient` uses the local `curl` binary so the project remains buildable without extra SDKs.

## Production hardening still pending

- Replace the simplified JSON request format with full JOSE/JWS request validation
- Add ACME order, authorization, challenge, finalize, and certificate download endpoints
- Verify JWS signatures cryptographically instead of only parsing envelope fields
- Add structured logging, metrics, TLS termination, and concurrency controls
