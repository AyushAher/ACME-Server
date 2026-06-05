#pragma once

#include "application/interfaces.h"

namespace acme::application {

class CertificateOrderService {
  public:
    CertificateOrderService(
        const AcmeAccountRepository& account_repository,
        const EabMappingRepository& eab_repository,
        const CertificateAuthority& certificate_authority);

    domain::CertificateIssueResult finalize_order(const domain::CertificateOrderRequest& request) const;

  private:
    const AcmeAccountRepository& account_repository_;
    const EabMappingRepository& eab_repository_;
    const CertificateAuthority& certificate_authority_;
};

}  // namespace acme::application
