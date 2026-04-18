#include "application/eab_service.h"

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/hmac_sha256.h"

namespace acme::application {

EabService::EabService(const EabMappingRepository& repository) : repository_(repository) {}

EabValidationResult EabService::validate(
    const domain::ExternalAccountBindingPayload& payload,
    const std::string& account_public_jwk) const {
    const auto mapping = repository_.find_by_client_id(payload.key_identifier);
    if (!mapping.has_value()) {
        return {.valid = false, .error = "unknown external account binding key identifier"};
    }
    if (payload.algorithm != "HS256") {
        return {.valid = false, .error = "unsupported EAB algorithm"};
    }
    if (payload.protected_jwk != account_public_jwk) {
        return {.valid = false, .error = "EAB payload JWK does not match account key"};
    }

    std::string hmac_key = mapping->hmac_key;
    if (mapping->hmac_key.find_first_of("-_") != std::string::npos || mapping->hmac_key.find('=') == std::string::npos) {
        const auto decoded = infrastructure::util::base64url_decode(mapping->hmac_key);
        if (!decoded.empty()) {
            hmac_key = decoded;
        }
    }

    const auto expected = infrastructure::util::hmac_sha256_base64url(
        hmac_key,
        payload.protected_header_b64 + "." + payload.payload_b64);

    if (expected != payload.signature) {
        return {.valid = false, .error = "EAB signature verification failed"};
    }

    return {.valid = true, .mapping = *mapping};
}

}  // namespace acme::application
