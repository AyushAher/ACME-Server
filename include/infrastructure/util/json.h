#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace acme::infrastructure::util::json {

std::optional<std::string> find_string(const std::string& json, const std::string& key);
std::optional<bool> find_bool(const std::string& json, const std::string& key);
std::vector<std::string> find_string_array(const std::string& json, const std::string& key);
std::optional<std::string> find_object(const std::string& json, const std::string& key);
std::string escape(const std::string& value);
std::string object(const std::map<std::string, std::string>& key_values, bool quote_values = false);

}  // namespace acme::infrastructure::util::json
