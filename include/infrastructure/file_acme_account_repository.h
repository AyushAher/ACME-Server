#pragma once

#include <string>
#include <vector>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileAcmeAccountRepository final : public application::AcmeAccountRepository {
  public:
    explicit FileAcmeAccountRepository(std::string file_path);
    std::optional<domain::AcmeAccount> find_by_public_jwk(const std::string& jwk) const override;
    domain::AcmeAccount save(const domain::AcmeAccount& account) override;
    std::optional<domain::AcmeAccount> find_by_id(const std::string& account_id) const override;
    std::optional<domain::AcmeAccount> find_by_key_id(const std::string& key_id) const override;

  private:
    std::string file_path_;
    std::vector<domain::AcmeAccount> load_all() const;
};

}  // namespace acme::infrastructure
