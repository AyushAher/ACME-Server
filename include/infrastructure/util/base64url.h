#pragma once

#include <string>

namespace acme::infrastructure::util {

std::string base64url_encode(const std::string& input);
std::string base64url_decode(const std::string& input);

}  // namespace acme::infrastructure::util
