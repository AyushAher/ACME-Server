#pragma once

#include <string>
#include <vector>

#include "domain/acme_types.h"

namespace acme::infrastructure {

std::string encode_list(const std::vector<std::string>& values);
std::vector<std::string> decode_list(const std::string& value);
std::string encode_identifiers(const std::vector<domain::Identifier>& identifiers);
std::vector<domain::Identifier> decode_identifiers(const std::string& value);
std::string encode_challenges(const std::vector<domain::AcmeChallenge>& challenges);
std::vector<domain::AcmeChallenge> decode_challenges(const std::string& value);

}  // namespace acme::infrastructure
