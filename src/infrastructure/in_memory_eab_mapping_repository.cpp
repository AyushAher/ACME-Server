#include "infrastructure/in_memory_eab_mapping_repository.h"

namespace acme::infrastructure {

InMemoryEabMappingRepository::InMemoryEabMappingRepository(std::vector<domain::EabMapping> mappings)
    : mappings_(std::move(mappings)) {}

std::optional<domain::EabMapping> InMemoryEabMappingRepository::find_by_client_id(
    const std::string& client_id) const {
    for (const auto& mapping : mappings_) {
        if (mapping.client_id == client_id) {
            return mapping;
        }
    }
    return std::nullopt;
}

}  // namespace acme::infrastructure
