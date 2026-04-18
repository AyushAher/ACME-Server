#include "application/certificate_order_service.h"

namespace acme::application {

CertificateOrderService::CertificateOrderService(
    const AcmeAccountRepository& account_repository,
    const EabMappingRepository& eab_repository,
    const CertificateAuthority& certificate_authority)
    : account_repository_(account_repository),
      eab_repository_(eab_repository),
      certificate_authority_(certificate_authority) {}

domain::CertificateIssueResult CertificateOrderService::finalize_order(
    const domain::CertificateOrderRequest& request) const {
    const auto account = account_repository_.find_by_id(request.account_id);
    if (!account.has_value()) {
        return {.error = "unknown ACME account"};
    }

    const auto mapping = eab_repository_.find_by_client_id(account->bound_client_id);
    if (!mapping.has_value()) {
        return {.error = "no EAB mapping associated with ACME account"};
    }

    if (mapping->ca != certificate_authority_.authority_name()) {
        return {.error = "configured certificate authority does not match bound CA"};
    }

    return certificate_authority_.issue_certificate(request, *mapping);
}

}  // namespace acme::application
