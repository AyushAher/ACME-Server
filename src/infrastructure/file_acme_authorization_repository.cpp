#include "infrastructure/file_acme_authorization_repository.h"

#include <filesystem>

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

namespace {

std::string join_encoded(const std::vector<std::string>& values) {
    std::string result;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            result += ",";
        }
        result += util::base64url_encode(values[index]);
    }
    return result;
}

std::vector<std::string> split_decoded(const std::string& value) {
    std::vector<std::string> items;
    for (const auto& part : util::split(value, ',')) {
        if (!part.empty()) {
            items.push_back(util::base64url_decode(part));
        }
    }
    return items;
}

}  // namespace

FileAcmeAuthorizationRepository::FileAcmeAuthorizationRepository(std::string data_dir)
    : data_dir_(std::move(data_dir)) {}

domain::AcmeAuthorization FileAcmeAuthorizationRepository::save(const domain::AcmeAuthorization& authorization) {
    return update(authorization);
}

domain::AcmeAuthorization FileAcmeAuthorizationRepository::update(const domain::AcmeAuthorization& authorization) {
    util::write_lines(
        path_for(authorization.authorization_id),
        {
            "authorization_id=" + util::base64url_encode(authorization.authorization_id),
            "account_id=" + util::base64url_encode(authorization.account_id),
            "order_id=" + util::base64url_encode(authorization.order_id),
            "status=" + util::base64url_encode(authorization.status),
            "identifier_type=" + util::base64url_encode(authorization.identifier_type),
            "identifier_value=" + util::base64url_encode(authorization.identifier_value),
            "expires_at=" + util::base64url_encode(authorization.expires_at),
            "challenges=" + join_encoded(encode_challenges(authorization.challenges)),
        });
    return authorization;
}

std::optional<domain::AcmeAuthorization> FileAcmeAuthorizationRepository::find_by_id(
    const std::string& authorization_id) const {
    const auto lines = util::read_lines(path_for(authorization_id));
    if (lines.empty()) {
        return std::nullopt;
    }

    domain::AcmeAuthorization authorization;
    for (const auto& line : lines) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "authorization_id") {
            authorization.authorization_id = util::base64url_decode(value);
        } else if (key == "account_id") {
            authorization.account_id = util::base64url_decode(value);
        } else if (key == "order_id") {
            authorization.order_id = util::base64url_decode(value);
        } else if (key == "status") {
            authorization.status = util::base64url_decode(value);
        } else if (key == "identifier_type") {
            authorization.identifier_type = util::base64url_decode(value);
        } else if (key == "identifier_value") {
            authorization.identifier_value = util::base64url_decode(value);
        } else if (key == "expires_at") {
            authorization.expires_at = util::base64url_decode(value);
        } else if (key == "challenges") {
            authorization.challenges = decode_challenges(split_decoded(value));
        }
    }
    return authorization;
}

std::optional<domain::AcmeAuthorization> FileAcmeAuthorizationRepository::find_by_challenge_id(
    const std::string& challenge_id) const {
    const auto directory = std::filesystem::path(data_dir_ + "/authorizations");
    if (!std::filesystem::exists(directory)) {
        return std::nullopt;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto authorization_id = entry.path().stem().string();
        const auto authorization = find_by_id(authorization_id);
        if (!authorization.has_value()) {
            continue;
        }
        for (const auto& challenge : authorization->challenges) {
            if (challenge.challenge_id == challenge_id) {
                return authorization;
            }
        }
    }
    return std::nullopt;
}

std::string FileAcmeAuthorizationRepository::path_for(const std::string& authorization_id) const {
    return data_dir_ + "/authorizations/" + authorization_id + ".record";
}

std::vector<std::string> FileAcmeAuthorizationRepository::encode_challenges(
    const std::vector<domain::AcmeChallenge>& challenges) {
    std::vector<std::string> values;
    for (const auto& challenge : challenges) {
        values.push_back(
            challenge.challenge_id + "|" + challenge.type + "|" + challenge.url + "|" + challenge.status + "|" +
            challenge.token + "|" + challenge.validated_at + "|" + challenge.error_detail + "|" +
            challenge.key_authorization);
    }
    return values;
}

std::vector<domain::AcmeChallenge> FileAcmeAuthorizationRepository::decode_challenges(
    const std::vector<std::string>& lines) {
    std::vector<domain::AcmeChallenge> challenges;
    for (const auto& line : lines) {
        const auto parts = util::split(line, '|');
        if (parts.size() != 8) {
            continue;
        }
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
    return challenges;
}

}  // namespace acme::infrastructure
