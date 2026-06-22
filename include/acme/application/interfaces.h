#pragma once

#include <optional>
#include <string>

#include "acme/domain/acme_types.h"
#include "acme/domain/eab_mapping.h"

namespace acme::application
{

  class EabMappingRepository
  {
  public:
    virtual ~EabMappingRepository() = default;
    virtual std::optional<domain::EabMapping> find_by_client_id(const std::string &client_id) const = 0;
  };

  class NonceRepository
  {
  public:
    virtual ~NonceRepository() = default;
    virtual std::string issue() = 0;
    virtual bool consume(const std::string &nonce) = 0;
  };

  class AcmeAccountRepository
  {
  public:
    virtual ~AcmeAccountRepository() = default;
    virtual std::optional<domain::AcmeAccount> find_by_public_jwk(const std::string &jwk) const = 0;
    virtual domain::AcmeAccount save(const domain::AcmeAccount &account) = 0;
    virtual std::optional<domain::AcmeAccount> find_by_id(const std::string &account_id) const = 0;
    virtual std::optional<domain::AcmeAccount> find_by_key_id(const std::string &key_id) const = 0;
  };

  class AcmeOrderRepository
  {
  public:
    virtual ~AcmeOrderRepository() = default;
    virtual domain::AcmeOrder save(const domain::AcmeOrder &order) = 0;
    virtual domain::AcmeOrder update(const domain::AcmeOrder &order) = 0;
    virtual std::optional<domain::AcmeOrder> find_by_id(const std::string &order_id) const = 0;
    virtual std::vector<domain::AcmeOrder> find_by_account_id(const std::string &account_id) const = 0;
  };

  class AcmeAuthorizationRepository
  {
  public:
    virtual ~AcmeAuthorizationRepository() = default;
    virtual domain::AcmeAuthorization save(const domain::AcmeAuthorization &authorization) = 0;
    virtual domain::AcmeAuthorization update(const domain::AcmeAuthorization &authorization) = 0;
    virtual std::optional<domain::AcmeAuthorization> find_by_id(const std::string &authorization_id) const = 0;
    virtual std::optional<domain::AcmeAuthorization> find_by_challenge_id(const std::string &challenge_id) const = 0;
    virtual std::optional<domain::AcmeAuthorization> find_by_challenge_token(const std::string &token) const = 0;
  };

  class AcmeCertificateRepository
  {
  public:
    virtual ~AcmeCertificateRepository() = default;
    virtual domain::AcmeCertificate save(const domain::AcmeCertificate &certificate) = 0;
    virtual std::optional<domain::AcmeCertificate> find_by_id(const std::string &certificate_id) const = 0;
  };

  class CertificateAuthority
  {
  public:
    virtual ~CertificateAuthority() = default;
    virtual std::string authority_name() const = 0;
    virtual bool supports_external_authorizations(const domain::EabMapping &mapping) const
    {
      (void)mapping;
      return false;
    }
    virtual domain::AcmeRelayOrderResult create_order(
        const std::string &account_id,
        const std::vector<domain::Identifier> &identifiers,
        const domain::EabMapping &mapping) const
    {
      (void)account_id;
      (void)identifiers;
      (void)mapping;
      return {.success = false, .error = "certificate authority does not support upstream ACME orders"};
    }
    virtual domain::CertificateIssueResult acknowledge_challenge(
        const std::string &challenge_url,
        const domain::EabMapping &mapping) const
    {
      (void)challenge_url;
      (void)mapping;
      return {.error = "certificate authority does not support upstream ACME challenges"};
    }
    virtual domain::CertificateIssueResult issue_certificate(
        const domain::CertificateOrderRequest &request,
        const domain::EabMapping &mapping) const = 0;

    virtual std::optional<domain::AcmeAuthorization> get_authorization(
        const std::string &authorization_url,
        const domain::EabMapping &mapping) const
    {
      (void)authorization_url;
      (void)mapping;
      return std::nullopt;
    }

    virtual bool client_account_matches_upstream(
        const std::string &client_account_jwk,
        const domain::EabMapping &mapping) const
    {
      (void)client_account_jwk;
      (void)mapping;
      return true;
    }

    virtual bool supports_http01_challenge_proxy(const domain::EabMapping &mapping) const
    {
      (void)mapping;
      return false;
    }

  };

  class ChallengeValidator
  {
  public:
    virtual ~ChallengeValidator() = default;
    virtual domain::CertificateIssueResult validate_http_01(
        const std::string &identifier,
        const std::string &token,
        const std::string &expected_key_authorization) const = 0;
  };

} // namespace acme::application
