#pragma once

#include <optional>
#include <string>
#include <vector>

namespace acme::infrastructure::util {

struct AcmeJwsEnvelope {
    std::string protected_b64;
    std::string payload_b64;
    std::string signature_b64;
    std::string protected_json;
    std::string payload_json;
    std::optional<std::string> url;
    std::optional<std::string> nonce;
    std::optional<std::string> kid;
    std::optional<std::string> jwk_json;
};

AcmeJwsEnvelope parse_acme_jws(const std::string& body);
std::string account_id_from_kid(const std::string& kid);
std::string der_base64url_to_pem_csr(const std::string& base64url_der);
std::vector<std::string> parse_order_identifiers(const std::string& payload_json);

}  // namespace acme::infrastructure::util
