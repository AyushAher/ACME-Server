#pragma once

#include "acme/application/interfaces.h"

namespace acme::infrastructure
{

  class RoutingCertificateAuthority final : public application::CertificateAuthority
  {
  public:
    RoutingCertificateAuthority(
        const application::CertificateAuthority &local_authority,
        const application::CertificateAuthority &upstream_authority);

    std::string authority_name() const override;
    bool supports_external_authorizations(const domain::EabMapping &mapping) const override;
    domain::AcmeRelayOrderResult create_order(
        const std::string &account_id,
        const std::vector<domain::Identifier> &identifiers,
        const domain::EabMapping &mapping) const override;
    domain::CertificateIssueResult acknowledge_challenge(
        const std::string &challenge_url,
        const domain::EabMapping &mapping) const override;
    domain::CertificateIssueResult issue_certificate(
        const domain::CertificateOrderRequest &request,
        const domain::EabMapping &mapping) const override;
    std::optional<domain::AcmeAuthorization> get_authorization(
        const std::string &authorization_url,
        const domain::EabMapping &mapping) const override;
    bool client_account_matches_upstream(
        const std::string &client_account_jwk,
        const domain::EabMapping &mapping) const override;
    bool supports_http01_challenge_proxy(const domain::EabMapping &mapping) const override;

  private:
    const application::CertificateAuthority &local_authority_;
    const application::CertificateAuthority &upstream_authority_;
  };

} // namespace acme::infrastructure
