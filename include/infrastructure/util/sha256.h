#pragma once

#include <string>

namespace acme::infrastructure::util {

std::string sha256_base64url(const std::string& payload);

}  // namespace acme::infrastructure::util
