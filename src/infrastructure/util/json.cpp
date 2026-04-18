#include "infrastructure/util/json.h"

#include <regex>
#include <sstream>

namespace acme::infrastructure::util::json {

namespace {

std::string unescape(std::string value) {
    std::string output;
    output.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            ++i;
            switch (value[i]) {
                case 'n':
                    output.push_back('\n');
                    break;
                case 'r':
                    output.push_back('\r');
                    break;
                case 't':
                    output.push_back('\t');
                    break;
                default:
                    output.push_back(value[i]);
                    break;
            }
        } else {
            output.push_back(value[i]);
        }
    }
    return output;
}

}  // namespace

std::optional<std::string> find_string(const std::string& json, const std::string& key) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return unescape(match[1].str());
    }
    return std::nullopt;
}

std::optional<bool> find_bool(const std::string& json, const std::string& key) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*(true|false)");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return match[1].str() == "true";
    }
    return std::nullopt;
}

std::vector<std::string> find_string_array(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::regex array_pattern("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]");
    std::smatch array_match;
    if (!std::regex_search(json, array_match, array_pattern)) {
        return values;
    }

    const std::regex string_pattern("\"((?:\\\\.|[^\"])*)\"");
    auto begin = std::sregex_iterator(array_match[1].first, array_match[1].second, string_pattern);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        values.push_back(unescape((*it)[1].str()));
    }
    return values;
}

std::optional<std::string> find_object(const std::string& json, const std::string& key) {
    const auto key_token = "\"" + key + "\"";
    const auto key_position = json.find(key_token);
    if (key_position == std::string::npos) {
        return std::nullopt;
    }
    const auto object_start = json.find('{', key_position);
    if (object_start == std::string::npos) {
        return std::nullopt;
    }

    int depth = 0;
    bool in_string = false;
    for (std::size_t index = object_start; index < json.size(); ++index) {
        const auto ch = json[index];
        if (ch == '"' && (index == 0 || json[index - 1] != '\\')) {
            in_string = !in_string;
        }
        if (in_string) {
            continue;
        }
        if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                return json.substr(object_start, index - object_start + 1);
            }
        }
    }
    return std::nullopt;
}

std::string escape(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (const auto ch : value) {
        switch (ch) {
            case '\\':
                output += "\\\\";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                output.push_back(ch);
                break;
        }
    }
    return output;
}

std::string object(const std::map<std::string, std::string>& key_values, bool quote_values) {
    std::ostringstream output;
    output << "{";
    bool first = true;
    for (const auto& [key, value] : key_values) {
        if (!first) {
            output << ",";
        }
        first = false;
        output << "\"" << escape(key) << "\":";
        if (quote_values) {
            output << "\"" << escape(value) << "\"";
        } else {
            output << value;
        }
    }
    output << "}";
    return output.str();
}

}  // namespace acme::infrastructure::util::json
