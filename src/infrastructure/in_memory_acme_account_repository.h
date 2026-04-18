#pragma once

#include <vector>

#include "application/interfaces.h"

namespace acme::infrastructure {

class InMemoryAcmeAccountRepository final : public application::AcmeAccountRepository {
  public:
    std::optional<domain::AcmeAccount> find_by_public_jwk(const std::string& jwk) const override;
    domain::AcmeAccount save(const domain::AcmeAccount& account) override;
    std::optional<domain::AcmeAccount> find_by_id(const std::string& account_id) const override;
    std::optional<domain::AcmeAccount> find_by_key_id(const std::string& key_id) const override;

  private:
    std::vector<domain::AcmeAccount> accounts_;
};

}  // namespace acme::infrastructure
