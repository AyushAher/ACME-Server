#pragma once

#include <string>

namespace acme::infrastructure::util {

std::string hmac_sha256_base64url(const std::string& key, const std::string& payload);

}  // namespace acme::infrastructure::util
