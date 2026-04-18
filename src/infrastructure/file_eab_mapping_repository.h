#pragma once

#include <string>
#include <vector>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileEabMappingRepository final : public application::EabMappingRepository {
  public:
    explicit FileEabMappingRepository(std::string file_path);
    std::optional<domain::EabMapping> find_by_client_id(const std::string& client_id) const override;

  private:
    std::string file_path_;
    std::vector<domain::EabMapping> load_all() const;
};

}  // namespace acme::infrastructure
