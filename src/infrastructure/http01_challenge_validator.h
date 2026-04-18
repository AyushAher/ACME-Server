#pragma once

#include "application/interfaces.h"

namespace acme::infrastructure {

class Http01ChallengeValidator final : public application::ChallengeValidator {
  public:
    domain::CertificateIssueResult validate_http_01(
        const std::string& identifier,
        const std::string& token,
        const std::string& expected_key_authorization) const override;
};

}  // namespace acme::infrastructure
