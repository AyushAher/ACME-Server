#pragma once

#include <string>
#include <vector>

namespace acme::infrastructure::util {

void ensure_parent_directory(const std::string& path);
std::vector<std::string> read_lines(const std::string& path);
void write_lines(const std::string& path, const std::vector<std::string>& lines);
void append_line(const std::string& path, const std::string& line);
std::vector<std::string> split(const std::string& value, char delimiter);

}  // namespace acme::infrastructure::util
