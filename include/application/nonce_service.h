#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::application {

class NonceService {
  public:
    explicit NonceService(NonceRepository& repository);
    std::string issue_nonce();
    bool consume_nonce(const std::string& nonce);

  private:
    NonceRepository& repository_;
};

}  // namespace acme::application
