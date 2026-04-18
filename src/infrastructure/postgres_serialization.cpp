#include "infrastructure/postgres_serialization.h"

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

std::string encode_list(const std::vector<std::string>& values) {
    std::string encoded;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            encoded += ",";
        }
        encoded += util::base64url_encode(values[index]);
    }
    return encoded;
}

std::vector<std::string> decode_list(const std::string& value) {
    std::vector<std::string> decoded;
    for (const auto& part : util::split(value, ',')) {
        if (!part.empty()) {
            decoded.push_back(util::base64url_decode(part));
        }
    }
    return decoded;
}

std::string encode_identifiers(const std::vector<domain::Identifier>& identifiers) {
    std::vector<std::string> items;
    for (const auto& identifier : identifiers) {
        items.push_back(identifier.type + "|" + identifier.value);
    }
    return encode_list(items);
}

std::vector<domain::Identifier> decode_identifiers(const std::string& value) {
    std::vector<domain::Identifier> identifiers;
    for (const auto& item : decode_list(value)) {
        const auto parts = util::split(item, '|');
        if (parts.size() == 2) {
            identifiers.push_back({.type = parts[0], .value = parts[1]});
        }
    }
    return identifiers;
}

std::string encode_challenges(const std::vector<domain::AcmeChallenge>& challenges) {
    std::vector<std::string> items;
    for (const auto& challenge : challenges) {
        items.push_back(
            challenge.challenge_id + "|" + challenge.type + "|" + challenge.url + "|" + challenge.status + "|" +
            challenge.token + "|" + challenge.validated_at + "|" + challenge.error_detail + "|" +
            challenge.key_authorization);
    }
    return encode_list(items);
}

std::vector<domain::AcmeChallenge> decode_challenges(const std::string& value) {
    std::vector<domain::AcmeChallenge> challenges;
    for (const auto& item : decode_list(value)) {
        const auto parts = util::split(item, '|');
        if (parts.size() == 8) {
            challenges.push_back({
                .challenge_id = parts[0],
                .type = parts[1],
                .url = parts[2],
                .status = parts[3],
                .token = parts[4],
                .validated_at = parts[5],
                .error_detail = parts[6],
                .key_authorization = parts[7],
            });
        }
    }
    return challenges;
}

}  // namespace acme::infrastructure
