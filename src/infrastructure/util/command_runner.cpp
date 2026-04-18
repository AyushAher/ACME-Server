#include "infrastructure/util/command_runner.h"

#include <array>
#include <cstdio>

namespace acme::infrastructure::util {

namespace {

std::string shell_escape(const std::string& value) {
    std::string escaped = "'";
    for (const auto ch : value) {
        if (ch == '\'') {
            escaped += "'\\''";
        } else {
            escaped.push_back(ch);
        }
    }
    escaped += "'";
    return escaped;
}

}  // namespace

CommandResult run_command(const std::string& command, const std::optional<std::string>& workdir) {
    std::string full_command;
    if (workdir.has_value()) {
        full_command = "cd " + shell_escape(*workdir) + " && " + command + " 2>&1";
    } else {
        full_command = command + " 2>&1";
    }

    std::array<char, 512> buffer {};
    std::string output;
    FILE* pipe = popen(full_command.c_str(), "r");
    if (pipe == nullptr) {
        return {.exit_code = -1, .output = "failed to start command"};
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    const auto status = pclose(pipe);
    return {.exit_code = status, .output = output};
}

}  // namespace acme::infrastructure::util
