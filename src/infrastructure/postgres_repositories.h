#pragma once

#include <memory>

#include "application/interfaces.h"
#include "infrastructure/postgres_client.h"

namespace acme::infrastructure {

class PostgresEabMappingRepository final : public application::EabMappingRepository {
  public:
    explicit PostgresEabMappingRepository(std::shared_ptr<PostgresClient> client);
    std::optional<domain::EabMapping> find_by_client_id(const std::string& client_id) const override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

class PostgresNonceRepository final : public application::NonceRepository {
  public:
    explicit PostgresNonceRepository(std::shared_ptr<PostgresClient> client);
    std::string issue() override;
    bool consume(const std::string& nonce) override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

class PostgresAcmeAccountRepository final : public application::AcmeAccountRepository {
  public:
    explicit PostgresAcmeAccountRepository(std::shared_ptr<PostgresClient> client);
    std::optional<domain::AcmeAccount> find_by_public_jwk(const std::string& jwk) const override;
    domain::AcmeAccount save(const domain::AcmeAccount& account) override;
    std::optional<domain::AcmeAccount> find_by_id(const std::string& account_id) const override;
    std::optional<domain::AcmeAccount> find_by_key_id(const std::string& key_id) const override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

class PostgresAcmeOrderRepository final : public application::AcmeOrderRepository {
  public:
    explicit PostgresAcmeOrderRepository(std::shared_ptr<PostgresClient> client);
    domain::AcmeOrder save(const domain::AcmeOrder& order) override;
    domain::AcmeOrder update(const domain::AcmeOrder& order) override;
    std::optional<domain::AcmeOrder> find_by_id(const std::string& order_id) const override;
    std::vector<domain::AcmeOrder> find_by_account_id(const std::string& account_id) const override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

class PostgresAcmeAuthorizationRepository final : public application::AcmeAuthorizationRepository {
  public:
    explicit PostgresAcmeAuthorizationRepository(std::shared_ptr<PostgresClient> client);
    domain::AcmeAuthorization save(const domain::AcmeAuthorization& authorization) override;
    domain::AcmeAuthorization update(const domain::AcmeAuthorization& authorization) override;
    std::optional<domain::AcmeAuthorization> find_by_id(const std::string& authorization_id) const override;
    std::optional<domain::AcmeAuthorization> find_by_challenge_id(const std::string& challenge_id) const override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

class PostgresAcmeCertificateRepository final : public application::AcmeCertificateRepository {
  public:
    explicit PostgresAcmeCertificateRepository(std::shared_ptr<PostgresClient> client);
    domain::AcmeCertificate save(const domain::AcmeCertificate& certificate) override;
    std::optional<domain::AcmeCertificate> find_by_id(const std::string& certificate_id) const override;

  private:
    std::shared_ptr<PostgresClient> client_;
};

}  // namespace acme::infrastructure
