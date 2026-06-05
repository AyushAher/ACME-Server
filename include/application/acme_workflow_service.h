#pragma once

#include "application/interfaces.h"

namespace acme::application {

class AcmeWorkflowService {
  public:
    AcmeWorkflowService(
        const AcmeAccountRepository& account_repository,
        const EabMappingRepository& eab_repository,
        AcmeOrderRepository& order_repository,
        AcmeAuthorizationRepository& authorization_repository,
        AcmeCertificateRepository& certificate_repository,
        const CertificateAuthority& certificate_authority,
        const ChallengeValidator& challenge_validator,
        std::string base_url);

    domain::AcmeOrder create_order(
        const std::string& account_id,
        const std::vector<domain::Identifier>& identifiers) const;
    std::optional<domain::AcmeAccount> get_account(const std::string& account_id) const;
    std::vector<domain::AcmeOrder> get_account_orders(const std::string& account_id) const;
    std::optional<domain::AcmeOrder> get_order(const std::string& order_id) const;
    std::optional<domain::AcmeAuthorization> get_authorization(const std::string& authorization_id) const;
    std::optional<domain::AcmeAuthorization> get_authorization_by_challenge(const std::string& challenge_id) const;
    std::optional<domain::AcmeChallenge> get_challenge(const std::string& challenge_id) const;
    domain::AcmeChallenge acknowledge_challenge(
        const std::string& challenge_id,
        const std::string& account_id,
        const std::optional<std::string>& supplied_key_authorization = std::nullopt) const;
    domain::AcmeOrder finalize_order(
        const std::string& order_id,
        const std::string& account_id,
        const std::string& csr_pem) const;
    std::optional<domain::AcmeCertificate> get_certificate(const std::string& certificate_id) const;

  private:
    const AcmeAccountRepository& account_repository_;
    const EabMappingRepository& eab_repository_;
    AcmeOrderRepository& order_repository_;
    AcmeAuthorizationRepository& authorization_repository_;
    AcmeCertificateRepository& certificate_repository_;
    const CertificateAuthority& certificate_authority_;
    const ChallengeValidator& challenge_validator_;
    std::string base_url_;

    static std::string next_id(const std::string& prefix);
    static std::string jwk_thumbprint(const std::string& jwk);
};

}  // namespace acme::application
