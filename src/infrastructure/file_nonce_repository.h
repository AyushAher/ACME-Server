#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileNonceRepository final : public application::NonceRepository {
  public:
    explicit FileNonceRepository(std::string file_path);
    std::string issue() override;
    bool consume(const std::string& nonce) override;

  private:
    std::string file_path_;
};

}  // namespace acme::infrastructure
