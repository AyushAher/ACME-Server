#include "infrastructure/postgres_repositories.h"

#include "infrastructure/postgres_serialization.h"
#include "infrastructure/util/random.h"

namespace acme::infrastructure {

namespace {

domain::AcmeAccount account_from_row(const std::vector<std::string>& row) {
    return {
        .account_id = row[0],
        .contacts = decode_list(row[1]),
        .account_public_jwk = row[2],
        .bound_client_id = row[3],
        .ca_name = row[4],
    };
}

domain::AcmeOrder order_from_row(const std::vector<std::string>& row) {
    return {
        .order_id = row[0],
        .account_id = row[1],
        .status = row[2],
        .expires_at = row[3],
        .finalize_url = row[4],
        .certificate_id = row[5],
        .certificate_url = row[6],
        .csr_pem = row[7],
        .authorization_ids = decode_list(row[8]),
        .identifiers = decode_identifiers(row[9]),
    };
}

domain::AcmeAuthorization authorization_from_row(const std::vector<std::string>& row) {
    return {
        .authorization_id = row[0],
        .account_id = row[1],
        .order_id = row[2],
        .status = row[3],
        .identifier_type = row[4],
        .identifier_value = row[5],
        .expires_at = row[6],
        .challenges = decode_challenges(row[7]),
    };
}

domain::AcmeCertificate certificate_from_row(const std::vector<std::string>& row) {
    return {
        .certificate_id = row[0],
        .order_id = row[1],
        .pem_chain = row[2],
        .leaf_pem = row[3],
        .issued_at = row[4],
        .serial_hex = row[5],
    };
}

}  // namespace

PostgresEabMappingRepository::PostgresEabMappingRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

std::optional<domain::EabMapping> PostgresEabMappingRepository::find_by_client_id(const std::string& client_id) const {
    const auto rows = client_->query(
        "select id, client_id, hmac_key, ca, credentials_id from eab_mappings where client_id = " +
        client_->escape_literal(client_id) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return domain::EabMapping {
        .id = rows[0][0],
        .client_id = rows[0][1],
        .hmac_key = rows[0][2],
        .ca = rows[0][3],
        .credentials_id = rows[0][4],
    };
}

PostgresNonceRepository::PostgresNonceRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

std::string PostgresNonceRepository::issue() {
    const auto nonce = util::random_token(18);
    client_->exec("insert into acme_nonces (nonce) values (" + client_->escape_literal(nonce) + ")");
    return nonce;
}

bool PostgresNonceRepository::consume(const std::string& nonce) {
    const auto rows = client_->query(
        "delete from acme_nonces where nonce = " + client_->escape_literal(nonce) + " returning nonce");
    return !rows.empty();
}

PostgresAcmeAccountRepository::PostgresAcmeAccountRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

std::optional<domain::AcmeAccount> PostgresAcmeAccountRepository::find_by_public_jwk(const std::string& jwk) const {
    const auto rows = client_->query(
        "select account_id, contacts_json, account_public_jwk, bound_client_id, ca_name from acme_accounts where account_public_jwk = " +
        client_->escape_literal(jwk) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return account_from_row(rows[0]);
}

domain::AcmeAccount PostgresAcmeAccountRepository::save(const domain::AcmeAccount& account) {
    client_->exec(
        "insert into acme_accounts (account_id, contacts_json, account_public_jwk, bound_client_id, ca_name) values (" +
        client_->escape_literal(account.account_id) + "," +
        client_->escape_literal(encode_list(account.contacts)) + "," +
        client_->escape_literal(account.account_public_jwk) + "," +
        client_->escape_literal(account.bound_client_id) + "," +
        client_->escape_literal(account.ca_name) + ") " +
        "on conflict (account_id) do update set contacts_json = excluded.contacts_json, account_public_jwk = excluded.account_public_jwk, bound_client_id = excluded.bound_client_id, ca_name = excluded.ca_name");
    return account;
}

std::optional<domain::AcmeAccount> PostgresAcmeAccountRepository::find_by_id(const std::string& account_id) const {
    const auto rows = client_->query(
        "select account_id, contacts_json, account_public_jwk, bound_client_id, ca_name from acme_accounts where account_id = " +
        client_->escape_literal(account_id) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return account_from_row(rows[0]);
}

std::optional<domain::AcmeAccount> PostgresAcmeAccountRepository::find_by_key_id(const std::string& key_id) const {
    return find_by_id(key_id);
}

PostgresAcmeOrderRepository::PostgresAcmeOrderRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

domain::AcmeOrder PostgresAcmeOrderRepository::save(const domain::AcmeOrder& order) { return update(order); }

domain::AcmeOrder PostgresAcmeOrderRepository::update(const domain::AcmeOrder& order) {
    client_->exec(
        "insert into acme_orders (order_id, account_id, status, expires_at, finalize_url, certificate_id, certificate_url, csr_pem, authorization_ids_json, identifiers_json) values (" +
        client_->escape_literal(order.order_id) + "," +
        client_->escape_literal(order.account_id) + "," +
        client_->escape_literal(order.status) + "," +
        client_->escape_literal(order.expires_at) + "," +
        client_->escape_literal(order.finalize_url) + "," +
        client_->escape_literal(order.certificate_id) + "," +
        client_->escape_literal(order.certificate_url) + "," +
        client_->escape_literal(order.csr_pem) + "," +
        client_->escape_literal(encode_list(order.authorization_ids)) + "," +
        client_->escape_literal(encode_identifiers(order.identifiers)) + ") " +
        "on conflict (order_id) do update set account_id = excluded.account_id, status = excluded.status, expires_at = excluded.expires_at, finalize_url = excluded.finalize_url, certificate_id = excluded.certificate_id, certificate_url = excluded.certificate_url, csr_pem = excluded.csr_pem, authorization_ids_json = excluded.authorization_ids_json, identifiers_json = excluded.identifiers_json");
    return order;
}

std::optional<domain::AcmeOrder> PostgresAcmeOrderRepository::find_by_id(const std::string& order_id) const {
    const auto rows = client_->query(
        "select order_id, account_id, status, expires_at, finalize_url, certificate_id, certificate_url, csr_pem, authorization_ids_json, identifiers_json from acme_orders where order_id = " +
        client_->escape_literal(order_id) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return order_from_row(rows[0]);
}

std::vector<domain::AcmeOrder> PostgresAcmeOrderRepository::find_by_account_id(const std::string& account_id) const {
    const auto rows = client_->query(
        "select order_id, account_id, status, expires_at, finalize_url, certificate_id, certificate_url, csr_pem, authorization_ids_json, identifiers_json from acme_orders where account_id = " +
        client_->escape_literal(account_id));
    std::vector<domain::AcmeOrder> orders;
    for (const auto& row : rows) {
        orders.push_back(order_from_row(row));
    }
    return orders;
}

PostgresAcmeAuthorizationRepository::PostgresAcmeAuthorizationRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

domain::AcmeAuthorization PostgresAcmeAuthorizationRepository::save(const domain::AcmeAuthorization& authorization) { return update(authorization); }

domain::AcmeAuthorization PostgresAcmeAuthorizationRepository::update(const domain::AcmeAuthorization& authorization) {
    client_->exec(
        "insert into acme_authorizations (authorization_id, account_id, order_id, status, identifier_type, identifier_value, expires_at, challenges_json) values (" +
        client_->escape_literal(authorization.authorization_id) + "," +
        client_->escape_literal(authorization.account_id) + "," +
        client_->escape_literal(authorization.order_id) + "," +
        client_->escape_literal(authorization.status) + "," +
        client_->escape_literal(authorization.identifier_type) + "," +
        client_->escape_literal(authorization.identifier_value) + "," +
        client_->escape_literal(authorization.expires_at) + "," +
        client_->escape_literal(encode_challenges(authorization.challenges)) + ") " +
        "on conflict (authorization_id) do update set account_id = excluded.account_id, order_id = excluded.order_id, status = excluded.status, identifier_type = excluded.identifier_type, identifier_value = excluded.identifier_value, expires_at = excluded.expires_at, challenges_json = excluded.challenges_json");
    return authorization;
}

std::optional<domain::AcmeAuthorization> PostgresAcmeAuthorizationRepository::find_by_id(const std::string& authorization_id) const {
    const auto rows = client_->query(
        "select authorization_id, account_id, order_id, status, identifier_type, identifier_value, expires_at, challenges_json from acme_authorizations where authorization_id = " +
        client_->escape_literal(authorization_id) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return authorization_from_row(rows[0]);
}

std::optional<domain::AcmeAuthorization> PostgresAcmeAuthorizationRepository::find_by_challenge_id(const std::string& challenge_id) const {
    const auto rows = client_->query(
        "select authorization_id, account_id, order_id, status, identifier_type, identifier_value, expires_at, challenges_json from acme_authorizations");
    for (const auto& row : rows) {
        auto authorization = authorization_from_row(row);
        for (const auto& challenge : authorization.challenges) {
            if (challenge.challenge_id == challenge_id) {
                return authorization;
            }
        }
    }
    return std::nullopt;
}

PostgresAcmeCertificateRepository::PostgresAcmeCertificateRepository(std::shared_ptr<PostgresClient> client) : client_(std::move(client)) {}

domain::AcmeCertificate PostgresAcmeCertificateRepository::save(const domain::AcmeCertificate& certificate) {
    client_->exec(
        "insert into acme_certificates (certificate_id, order_id, pem_chain, leaf_pem, issued_at, serial_hex) values (" +
        client_->escape_literal(certificate.certificate_id) + "," +
        client_->escape_literal(certificate.order_id) + "," +
        client_->escape_literal(certificate.pem_chain) + "," +
        client_->escape_literal(certificate.leaf_pem) + "," +
        client_->escape_literal(certificate.issued_at) + "," +
        client_->escape_literal(certificate.serial_hex) + ") " +
        "on conflict (certificate_id) do update set order_id = excluded.order_id, pem_chain = excluded.pem_chain, leaf_pem = excluded.leaf_pem, issued_at = excluded.issued_at, serial_hex = excluded.serial_hex");
    return certificate;
}

std::optional<domain::AcmeCertificate> PostgresAcmeCertificateRepository::find_by_id(const std::string& certificate_id) const {
    const auto rows = client_->query(
        "select certificate_id, order_id, pem_chain, leaf_pem, issued_at, serial_hex from acme_certificates where certificate_id = " +
        client_->escape_literal(certificate_id) + " limit 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return certificate_from_row(rows[0]);
}

}  // namespace acme::infrastructure
