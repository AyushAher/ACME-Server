#pragma once

#include <string>

namespace acme::infrastructure::util {

std::string random_token(std::size_t bytes = 24);
std::string now_rfc3339();

}  // namespace acme::infrastructure::util
