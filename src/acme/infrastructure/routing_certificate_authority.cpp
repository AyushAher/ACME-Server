#include "acme/infrastructure/routing_certificate_authority.h"

#include <iostream>

namespace acme::infrastructure
{
    RoutingCertificateAuthority::RoutingCertificateAuthority(
        const application::CertificateAuthority &local_authority,
        const application::CertificateAuthority &upstream_authority)
        : local_authority_(local_authority), upstream_authority_(upstream_authority) {}

    std::string RoutingCertificateAuthority::authority_name() const
    {
        return "*";
    }

    bool RoutingCertificateAuthority::supports_external_authorizations(const domain::EabMapping &mapping) const
    {
        return upstream_authority_.supports_external_authorizations(mapping);
    }

    domain::AcmeRelayOrderResult RoutingCertificateAuthority::create_order(
        const std::string &account_id,
        const std::vector<domain::Identifier> &identifiers,
        const domain::EabMapping &mapping) const
    {
        return upstream_authority_.create_order(account_id, identifiers, mapping);
    }

    domain::CertificateIssueResult RoutingCertificateAuthority::acknowledge_challenge(
        const std::string &challenge_url,
        const domain::EabMapping &mapping) const
    {
        return upstream_authority_.acknowledge_challenge(challenge_url, mapping);
    }

    std::optional<domain::AcmeAuthorization> RoutingCertificateAuthority::get_authorization(
        const std::string &authorization_url,
        const domain::EabMapping &mapping) const
    {
        return upstream_authority_.get_authorization(authorization_url, mapping);
    }

    bool RoutingCertificateAuthority::client_account_matches_upstream(
        const std::string &client_account_jwk,
        const domain::EabMapping &mapping) const
    {
        return upstream_authority_.client_account_matches_upstream(client_account_jwk, mapping);
    }

    bool RoutingCertificateAuthority::supports_http01_challenge_proxy(
        const domain::EabMapping &mapping) const
    {
        return upstream_authority_.supports_http01_challenge_proxy(mapping);
    }

    domain::CertificateIssueResult RoutingCertificateAuthority::issue_certificate(
        const domain::CertificateOrderRequest &request,
        const domain::EabMapping &mapping) const
    {
        if (upstream_authority_.supports_external_authorizations(mapping))
        {
            std::cout << "[acme] certificate issuer=upstream-acme ca=" << mapping.ca
                      << " credentials_id=" << mapping.credentials_id << "\n";
            return upstream_authority_.issue_certificate(request, mapping);
        }
        std::cout << "[acme] certificate issuer=local ca=" << mapping.ca
                  << " credentials_id=" << mapping.credentials_id << "\n";
        return local_authority_.issue_certificate(request, mapping);
    }

} // namespace acme::infrastructure
