#include "infrastructure/in_memory_acme_account_repository.h"

namespace acme::infrastructure {

std::optional<domain::AcmeAccount> InMemoryAcmeAccountRepository::find_by_public_jwk(
    const std::string& jwk) const {
    for (const auto& account : accounts_) {
        if (account.account_public_jwk == jwk) {
            return account;
        }
    }
    return std::nullopt;
}

domain::AcmeAccount InMemoryAcmeAccountRepository::save(const domain::AcmeAccount& account) {
    accounts_.push_back(account);
    return account;
}

std::optional<domain::AcmeAccount> InMemoryAcmeAccountRepository::find_by_id(const std::string& account_id) const {
    for (const auto& account : accounts_) {
        if (account.account_id == account_id) {
            return account;
        }
    }
    return std::nullopt;
}

std::optional<domain::AcmeAccount> InMemoryAcmeAccountRepository::find_by_key_id(const std::string& key_id) const {
    return find_by_id(key_id);
}

}  // namespace acme::infrastructure
