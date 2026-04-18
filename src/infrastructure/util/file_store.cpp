#include "infrastructure/util/file_store.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace acme::infrastructure::util {

void ensure_parent_directory(const std::string& path) {
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }
}

std::vector<std::string> read_lines(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return {};
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return lines;
}

void write_lines(const std::string& path, const std::vector<std::string>& lines) {
    ensure_parent_directory(path);
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("unable to write file: " + path);
    }
    for (const auto& line : lines) {
        output << line << "\n";
    }
}

void append_line(const std::string& path, const std::string& line) {
    ensure_parent_directory(path);
    std::ofstream output(path, std::ios::app);
    if (!output.is_open()) {
        throw std::runtime_error("unable to append file: " + path);
    }
    output << line << "\n";
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    for (const auto ch : value) {
        if (ch == delimiter) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    parts.push_back(current);
    return parts;
}

}  // namespace acme::infrastructure::util
