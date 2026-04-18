#include "infrastructure/file_eab_mapping_repository.h"

#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

FileEabMappingRepository::FileEabMappingRepository(std::string file_path) : file_path_(std::move(file_path)) {}

std::optional<domain::EabMapping> FileEabMappingRepository::find_by_client_id(const std::string& client_id) const {
    for (const auto& mapping : load_all()) {
        if (mapping.client_id == client_id) {
            return mapping;
        }
    }
    return std::nullopt;
}

std::vector<domain::EabMapping> FileEabMappingRepository::load_all() const {
    const auto lines = util::read_lines(file_path_);
    std::vector<domain::EabMapping> mappings;
    bool first = true;
    for (const auto& line : lines) {
        if (line.empty()) {
            continue;
        }
        if (first) {
            first = false;
            if (line.starts_with("id,")) {
                continue;
            }
        }
        const auto parts = util::split(line, ',');
        if (parts.size() != 5) {
            continue;
        }
        mappings.push_back({
            .id = parts[0],
            .client_id = parts[1],
            .hmac_key = parts[2],
            .ca = parts[3],
            .credentials_id = parts[4],
        });
    }
    return mappings;
}

}  // namespace acme::infrastructure
