create table if not exists eab_mappings (
    id text primary key,
    client_id text not null unique,
    hmac_key text not null,
    ca text not null,
    credentials_id text not null
);

create table if not exists acme_accounts (
    account_id text primary key,
    contacts_json text not null,
    account_public_jwk text not null unique,
    bound_client_id text not null,
    ca_name text not null
);

create table if not exists acme_nonces (
    nonce text primary key,
    created_at timestamptz not null default now()
);

create table if not exists acme_orders (
    order_id text primary key,
    account_id text not null,
    status text not null,
    expires_at text not null,
    finalize_url text not null,
    certificate_id text not null default '',
    certificate_url text not null default '',
    csr_pem text not null default '',
    authorization_ids_json text not null,
    identifiers_json text not null
);

create table if not exists acme_authorizations (
    authorization_id text primary key,
    account_id text not null,
    order_id text not null,
    status text not null,
    identifier_type text not null,
    identifier_value text not null,
    expires_at text not null,
    challenges_json text not null
);

create table if not exists acme_certificates (
    certificate_id text primary key,
    order_id text not null,
    pem_chain text not null,
    leaf_pem text not null,
    issued_at text not null,
    serial_hex text not null
);
