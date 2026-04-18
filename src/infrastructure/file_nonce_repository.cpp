#include "infrastructure/file_nonce_repository.h"

#include "infrastructure/util/file_store.h"
#include "infrastructure/util/random.h"

namespace acme::infrastructure {

FileNonceRepository::FileNonceRepository(std::string file_path) : file_path_(std::move(file_path)) {}

std::string FileNonceRepository::issue() {
    const auto nonce = util::random_token(18);
    util::append_line(file_path_, nonce);
    return nonce;
}

bool FileNonceRepository::consume(const std::string& nonce) {
    const auto lines = util::read_lines(file_path_);
    std::vector<std::string> retained;
    bool found = false;
    for (const auto& line : lines) {
        if (!found && line == nonce) {
            found = true;
            continue;
        }
        if (!line.empty()) {
            retained.push_back(line);
        }
    }
    if (found) {
        util::write_lines(file_path_, retained);
    }
    return found;
}

}  // namespace acme::infrastructure
