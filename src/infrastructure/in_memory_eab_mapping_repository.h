#pragma once

#include <vector>

#include "application/interfaces.h"

namespace acme::infrastructure {

class InMemoryEabMappingRepository final : public application::EabMappingRepository {
  public:
    explicit InMemoryEabMappingRepository(std::vector<domain::EabMapping> mappings);
    std::optional<domain::EabMapping> find_by_client_id(const std::string& client_id) const override;

  private:
    std::vector<domain::EabMapping> mappings_;
};

}  // namespace acme::infrastructure
