#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::application {

struct EabValidationResult {
    bool valid {false};
    std::string error;
    domain::EabMapping mapping;
};

class EabService {
  public:
    explicit EabService(const EabMappingRepository& repository);
    EabValidationResult validate(
        const domain::ExternalAccountBindingPayload& payload,
        const std::string& account_public_jwk) const;

  private:
    const EabMappingRepository& repository_;
};

}  // namespace acme::application
