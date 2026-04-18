#include <memory>

#include "application/acme_account_service.h"
#include "application/acme_workflow_service.h"
#include "application/eab_service.h"
#include "application/nonce_service.h"
#include "infrastructure/config/app_config.h"
#include "infrastructure/file_acme_authorization_repository.h"
#include "infrastructure/file_acme_account_repository.h"
#include "infrastructure/file_acme_certificate_repository.h"
#include "infrastructure/file_eab_mapping_repository.h"
#include "infrastructure/file_acme_order_repository.h"
#include "infrastructure/file_nonce_repository.h"
#include "infrastructure/http01_challenge_validator.h"
#include "infrastructure/openssl_certificate_authority.h"
#include "infrastructure/postgres_client.h"
#include "infrastructure/postgres_repositories.h"
#include "infrastructure/transport/acme_http_server.h"
#include "infrastructure/util/file_store.h"

namespace {

void seed_postgres_eab_mappings(
    const std::shared_ptr<acme::infrastructure::PostgresClient>& postgres_client,
    const std::string& csv_path) {
    using acme::infrastructure::util::read_lines;
    using acme::infrastructure::util::split;

    bool first = true;
    for (const auto& line : read_lines(csv_path)) {
        if (line.empty()) {
            continue;
        }
        if (first) {
            first = false;
            if (line.starts_with("id,")) {
                continue;
            }
        }
        const auto parts = split(line, ',');
        if (parts.size() != 5) {
            continue;
        }
        postgres_client->exec(
            "insert into eab_mappings (id, client_id, hmac_key, ca, credentials_id) values (" +
            postgres_client->escape_literal(parts[0]) + "," +
            postgres_client->escape_literal(parts[1]) + "," +
            postgres_client->escape_literal(parts[2]) + "," +
            postgres_client->escape_literal(parts[3]) + "," +
            postgres_client->escape_literal(parts[4]) + ") " +
            "on conflict (client_id) do update set hmac_key = excluded.hmac_key, ca = excluded.ca, credentials_id = excluded.credentials_id");
    }
}

}  // namespace

int main() {
    using namespace acme;
    const auto config = infrastructure::config::load_from_file("config/server.conf");
    std::shared_ptr<infrastructure::PostgresClient> postgres_client;
    std::unique_ptr<application::EabMappingRepository> eab_repository;
    std::unique_ptr<application::AcmeAccountRepository> account_repository;
    std::unique_ptr<application::AcmeOrderRepository> order_repository;
    std::unique_ptr<application::AcmeAuthorizationRepository> authorization_repository;
    std::unique_ptr<application::AcmeCertificateRepository> certificate_repository;
    std::unique_ptr<application::NonceRepository> nonce_repository;

    if (config.storage_backend == "postgres") {
        postgres_client = std::make_shared<infrastructure::PostgresClient>(config.postgres_connection_string);
        postgres_client->ensure_schema("sql/postgres_schema.sql");
        seed_postgres_eab_mappings(postgres_client, config.eab_mappings_file);
        eab_repository = std::make_unique<infrastructure::PostgresEabMappingRepository>(postgres_client);
        account_repository = std::make_unique<infrastructure::PostgresAcmeAccountRepository>(postgres_client);
        order_repository = std::make_unique<infrastructure::PostgresAcmeOrderRepository>(postgres_client);
        authorization_repository = std::make_unique<infrastructure::PostgresAcmeAuthorizationRepository>(postgres_client);
        certificate_repository = std::make_unique<infrastructure::PostgresAcmeCertificateRepository>(postgres_client);
        nonce_repository = std::make_unique<infrastructure::PostgresNonceRepository>(postgres_client);
    } else {
        eab_repository = std::make_unique<infrastructure::FileEabMappingRepository>(config.eab_mappings_file);
        account_repository = std::make_unique<infrastructure::FileAcmeAccountRepository>(config.accounts_file);
        order_repository = std::make_unique<infrastructure::FileAcmeOrderRepository>(config.data_dir);
        authorization_repository = std::make_unique<infrastructure::FileAcmeAuthorizationRepository>(config.data_dir);
        certificate_repository = std::make_unique<infrastructure::FileAcmeCertificateRepository>(config.data_dir);
        nonce_repository = std::make_unique<infrastructure::FileNonceRepository>(config.nonces_file);
    }

    infrastructure::Http01ChallengeValidator challenge_validator;
    infrastructure::OpenSslCertificateAuthority certificate_authority({
        .ca_name = config.openssl_ca_name,
        .intermediate_dir = config.openssl_intermediate_dir,
        .chain_file = config.openssl_chain_file,
        .working_dir = config.data_dir,
        .valid_days = config.openssl_valid_days,
    });

    application::EabService eab_service(*eab_repository);
    application::AcmeAccountService account_service(*account_repository, eab_service);
    application::NonceService nonce_service(*nonce_repository);
    application::AcmeWorkflowService workflow_service(
        *account_repository,
        *eab_repository,
        *order_repository,
        *authorization_repository,
        *certificate_repository,
        certificate_authority,
        challenge_validator,
        config.base_url);

    infrastructure::transport::AcmeHttpServer server(
        {
            .host = config.host,
            .port = config.port,
            .base_url = config.base_url,
        },
        nonce_service,
        account_service,
        workflow_service);

    server.run();
    return 0;
}
