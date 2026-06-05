#pragma once

#include <set>
#include <string>

#include "application/interfaces.h"

namespace acme::infrastructure {

class InMemoryNonceRepository final : public application::NonceRepository {
  public:
    std::string issue() override;
    bool consume(const std::string& nonce) override;

  private:
    std::set<std::string> live_nonces_;
    std::size_t counter_ {1};
};

}  // namespace acme::infrastructure
