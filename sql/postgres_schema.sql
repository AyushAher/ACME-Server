create table if not exists eab_mappings (
    id text primary key,
    client_id text not null unique,
    hmac_key text not null,
    ca text not null,
    credentials_id text not null
);

create table if not exists ca_credentials (
    id text primary key,
    ca_name text not null,
    ca_type text not null default 'acme',
    directory_url text not null,
    eab_kid text not null default '',
    eab_hmac_key text not null default '',
    account_key_pem text not null default '',
    account_url text not null default '',
    terms_of_service_agreed boolean not null default true,
    insecure_skip_tls_verify boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

insert into ca_credentials (id, ca_name, ca_type, directory_url, eab_kid, eab_hmac_key)
values
    ('letsencrypt-production', 'LetsEncrypt-Production', 'acme', 'https://acme-v02.api.letsencrypt.org/directory', '', ''),
    ('letsencrypt-staging', 'LetsEncrypt-Staging', 'acme', 'https://acme-staging-v02.api.letsencrypt.org/directory', '', '')
on conflict (id) do nothing;

insert into eab_mappings (id, client_id, hmac_key, ca, credentials_id)
values
    ('eab-letsencrypt-staging-demo', 'client-letsencrypt-staging-demo', 'replace-with-base64url-hmac-key', 'LetsEncrypt-Staging', 'letsencrypt-staging')
on conflict (client_id) do nothing;

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

alter table acme_orders add column if not exists upstream_url text not null default '';
alter table acme_orders add column if not exists upstream_finalize_url text not null default '';
alter table acme_orders add column if not exists upstream_certificate_url text not null default '';

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

alter table acme_authorizations add column if not exists upstream_url text not null default '';

create table if not exists acme_certificates (
    certificate_id text primary key,
    order_id text not null,
    pem_chain text not null,
    leaf_pem text not null,
    issued_at text not null,
    serial_hex text not null
);
