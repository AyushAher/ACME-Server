#pragma once

#include <string>

#include "acme/application/interfaces.h"

namespace acme::infrastructure
{

  class Http01WebrootPublisher final
  {
  public:
    explicit Http01WebrootPublisher(std::string webroot);

    bool configured() const;
    domain::CertificateIssueResult publish(
        const std::string &token,
        const std::string &key_authorization) const;

  private:
    std::string webroot_;
  };

} // namespace acme::infrastructure
