#pragma once

#include <optional>
#include <string>

namespace acme::infrastructure::util {

struct CommandResult {
    int exit_code {0};
    std::string output;
};

CommandResult run_command(const std::string& command, const std::optional<std::string>& workdir = std::nullopt);

}  // namespace acme::infrastructure::util
