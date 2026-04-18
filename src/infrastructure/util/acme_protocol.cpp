#include "infrastructure/util/acme_protocol.h"

#include <regex>
#include <stdexcept>

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/json.h"

namespace acme::infrastructure::util {

AcmeJwsEnvelope parse_acme_jws(const std::string& body) {
    using json::find_object;
    using json::find_string;

    const auto protected_b64 = find_string(body, "protected");
    const auto payload_b64 = find_string(body, "payload");
    const auto signature_b64 = find_string(body, "signature");

    if (!protected_b64.has_value() || !payload_b64.has_value() || !signature_b64.has_value()) {
        throw std::runtime_error("invalid ACME JWS envelope");
    }

    AcmeJwsEnvelope envelope;
    envelope.protected_b64 = *protected_b64;
    envelope.payload_b64 = *payload_b64;
    envelope.signature_b64 = *signature_b64;
    envelope.protected_json = base64url_decode(*protected_b64);
    envelope.payload_json = base64url_decode(*payload_b64);
    envelope.url = find_string(envelope.protected_json, "url");
    envelope.nonce = find_string(envelope.protected_json, "nonce");
    envelope.kid = find_string(envelope.protected_json, "kid");
    envelope.jwk_json = find_object(envelope.protected_json, "jwk");
    return envelope;
}

std::string account_id_from_kid(const std::string& kid) {
    const auto marker = std::string("/acme/acct/");
    const auto index = kid.rfind(marker);
    if (index == std::string::npos) {
        throw std::runtime_error("unsupported kid format");
    }
    return kid.substr(index + marker.size());
}

std::string der_base64url_to_pem_csr(const std::string& base64url_der) {
    const auto der = base64url_decode(base64url_der);
    std::string standard_b64;
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0;
    int valb = -6;
    for (const auto ch : der) {
        val = (val << 8) + static_cast<unsigned char>(ch);
        valb += 8;
        while (valb >= 0) {
            standard_b64.push_back(alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        standard_b64.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (standard_b64.size() % 4 != 0) {
        standard_b64.push_back('=');
    }

    std::string pem = "-----BEGIN CERTIFICATE REQUEST-----\n";
    for (std::size_t i = 0; i < standard_b64.size(); i += 64) {
        pem += standard_b64.substr(i, 64) + "\n";
    }
    pem += "-----END CERTIFICATE REQUEST-----\n";
    return pem;
}

std::vector<std::string> parse_order_identifiers(const std::string& payload_json) {
    const std::regex object_pattern("\\{\\s*\"type\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"value\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
    std::vector<std::string> values;
    auto begin = std::sregex_iterator(payload_json.begin(), payload_json.end(), object_pattern);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        values.push_back((*it)[1].str() + "|" + (*it)[2].str());
    }
    return values;
}

}  // namespace acme::infrastructure::util
