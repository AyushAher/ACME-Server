#pragma once

#include <optional>
#include <string>
#include <vector>

namespace acme::domain
{

    struct ExternalAccountBindingPayload
    {
        std::string key_identifier;
        std::string protected_jwk;
        std::string protected_header_b64;
        std::string payload_b64;
        std::string signature;
        std::string algorithm{"HS256"};
    };

    struct NewAccountRequest
    {
        std::vector<std::string> contacts;
        bool terms_of_service_agreed{false};
        std::string account_public_jwk;
        std::optional<ExternalAccountBindingPayload> external_account_binding;
    };

    struct AcmeAccount
    {
        std::string account_id;
        std::vector<std::string> contacts;
        std::string account_public_jwk;
        std::string bound_client_id;
        std::string ca_name;
    };

    struct Identifier
    {
        std::string type;
        std::string value;
    };

    struct AcmeChallenge
    {
        std::string challenge_id;
        std::string type;
        std::string url;
        std::string status{"pending"};
        std::string token;
        std::string validated_at;
        std::string error_detail;
        std::string key_authorization;
        std::string upstream_url;
    };

    struct AcmeAuthorization
    {
        std::string authorization_id;
        std::string account_id;
        std::string order_id;
        std::string status{"pending"};
        std::string identifier_type;
        std::string identifier_value;
        std::string expires_at;
        std::vector<AcmeChallenge> challenges;
        std::string upstream_url;
    };

    struct AcmeOrder
    {
        std::string order_id;
        std::string account_id;
        std::string status{"pending"};
        std::string expires_at;
        std::string finalize_url;
        std::string certificate_id;
        std::string certificate_url;
        std::string csr_pem;
        std::vector<std::string> authorization_ids;
        std::vector<Identifier> identifiers;
        std::string upstream_url;
        std::string upstream_finalize_url;
        std::string upstream_certificate_url;
    };

    struct AcmeCertificate
    {
        std::string certificate_id;
        std::string order_id;
        std::string pem_chain;
        std::string leaf_pem;
        std::string issued_at;
        std::string serial_hex;
    };

    struct NewAccountResponse
    {
        std::string account_id;
        std::string location;
        bool created{false};
    };

    struct CertificateOrderRequest
    {
        std::string account_id;
        std::string csr_pem;
        std::string certificate_profile_name;
        std::string end_entity_profile_name;
        std::string username;
        std::string enrollment_code;
        std::optional<std::string> email;
        bool include_chain{true};
        std::vector<Identifier> identifiers;
    };

    struct CertificateIssueResult
    {
        bool success{false};
        std::string certificate_pem_or_der;
        std::string raw_response;
        std::string error;
    };

    struct CaCredential
    {
        std::string id;
        std::string ca_name;
        std::string ca_type;
        std::string directory_url;
        std::string eab_kid;
        std::string eab_hmac_key;
        std::string account_key_pem;
        std::string account_url;
        bool terms_of_service_agreed{true};
        bool insecure_skip_tls_verify{false};
    };

    struct AcmeRelayOrderResult
    {
        bool success{false};
        std::string status{"pending"};
        std::string upstream_order_url;
        std::string upstream_finalize_url;
        std::string upstream_certificate_url;
        std::string raw_response;
        std::string error;
        std::vector<AcmeAuthorization> authorizations;
    };

} // namespace acme::domain
