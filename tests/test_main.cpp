#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "application/acme_account_service.h"
#include "application/certificate_order_service.h"
#include "application/eab_service.h"
#include "application/nonce_service.h"
#include "infrastructure/util/base64url.h"
#include "infrastructure/in_memory_acme_account_repository.h"
#include "infrastructure/in_memory_eab_mapping_repository.h"
#include "infrastructure/in_memory_nonce_repository.h"
#include "infrastructure/util/hmac_sha256.h"

namespace {

class StubCertificateAuthority final : public acme::application::CertificateAuthority {
  public:
    std::string authority_name() const override {
        return "EJBCA-Community";
    }

    acme::domain::CertificateIssueResult issue_certificate(
        const acme::domain::CertificateOrderRequest& request,
        const acme::domain::EabMapping& mapping) const override {
        return {
            .success = true,
            .certificate_pem_or_der = "issued-for:" + request.username + ":" + mapping.client_id,
            .raw_response = "ok",
        };
    }
};

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace

int main() {
    using namespace acme;

    infrastructure::InMemoryEabMappingRepository eab_repository({
        {
            .id = "1",
            .client_id = "client-123",
            .hmac_key = "dG9wLXNlY3JldA",
            .ca = "EJBCA-Community",
            .credentials_id = "cred-1",
        },
    });
    infrastructure::InMemoryAcmeAccountRepository account_repository;
    infrastructure::InMemoryNonceRepository nonce_repository;

    application::NonceService nonce_service(nonce_repository);
    const auto nonce = nonce_service.issue_nonce();
    expect(nonce_service.consume_nonce(nonce), "issued nonce should be consumable exactly once");
    expect(!nonce_service.consume_nonce(nonce), "consumed nonce should not be reusable");

    application::EabService eab_service(eab_repository);
    application::AcmeAccountService account_service(account_repository, eab_service);

    const std::string jwk = R"({"kty":"RSA","n":"abc","e":"AQAB"})";
    const std::string eab_protected = R"({"alg":"HS256","kid":"client-123","url":"https://acme.internal/acme/newAccount"})";
    const auto protected_b64 = infrastructure::util::base64url_encode(eab_protected);
    const auto payload_b64 = infrastructure::util::base64url_encode(jwk);
    const auto signature =
        infrastructure::util::hmac_sha256_base64url("top-secret", protected_b64 + "." + payload_b64);

    const auto account = account_service.register_account({
        .contacts = {"mailto:test@example.com"},
        .terms_of_service_agreed = true,
        .account_public_jwk = jwk,
        .external_account_binding = domain::ExternalAccountBindingPayload {
            .key_identifier = "client-123",
            .protected_jwk = jwk,
            .protected_header_b64 = protected_b64,
            .payload_b64 = payload_b64,
            .signature = signature,
            .algorithm = "HS256",
        },
    });

    expect(account.created, "new account should be created");

    StubCertificateAuthority ca;
    application::CertificateOrderService order_service(account_repository, eab_repository, ca);
    const auto result = order_service.finalize_order({
        .account_id = account.account_id,
        .csr_pem = "csr",
        .certificate_profile_name = "ServerTLS",
        .end_entity_profile_name = "AcmeServers",
        .username = "host-1",
        .enrollment_code = "secret",
        .include_chain = true,
    });

    expect(result.success, "certificate issuance should succeed");
    expect(result.certificate_pem_or_der == "issued-for:host-1:client-123", "issued certificate payload should match");

    std::cout << "All tests passed\n";
    return EXIT_SUCCESS;
}
