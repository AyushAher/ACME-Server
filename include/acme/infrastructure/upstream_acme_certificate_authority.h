#pragma once

#include <memory>

#include "acme/application/interfaces.h"
#include "acme/infrastructure/postgres_repositories.h"
#include "acme/infrastructure/shell_http_client.h"

namespace acme::infrastructure
{

    class UpstreamAcmeCertificateAuthority final : public application::CertificateAuthority
    {
    public:
        UpstreamAcmeCertificateAuthority(
            std::shared_ptr<PostgresCaCredentialRepository> credentials,
            std::string working_dir);

        std::string authority_name() const override;
        bool supports_external_authorizations(const domain::EabMapping &mapping) const override;
        domain::AcmeRelayOrderResult create_order(
            const std::string &account_id,
            const std::vector<domain::Identifier> &identifiers,
            const domain::EabMapping &mapping) const override;
        domain::CertificateIssueResult acknowledge_challenge(
            const std::string &challenge_url,
            const domain::EabMapping &mapping) const override;
        // line ~99
        std::optional<domain::AcmeAuthorization> get_authorization(
            const std::string &authorization_url,
            const domain::EabMapping &mapping) const override;
        bool client_account_matches_upstream(
            const std::string &client_account_jwk,
            const domain::EabMapping &mapping) const override;
        bool supports_http01_challenge_proxy(const domain::EabMapping &mapping) const override;
        domain::CertificateIssueResult issue_certificate(
            const domain::CertificateOrderRequest &request,
            const domain::EabMapping &mapping) const override;

    private:
        std::shared_ptr<PostgresCaCredentialRepository> credentials_;
        std::string working_dir_;
        ShellHttpClient http_;

        domain::CaCredential credential_for(const domain::EabMapping &mapping) const;
    };

} // namespace acme::infrastructure
