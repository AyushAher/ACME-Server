#include "application/acme_account_service.h"

#include <stdexcept>

#include "infrastructure/util/random.h"

namespace acme::application {

AcmeAccountService::AcmeAccountService(
    AcmeAccountRepository& repository,
    const EabService& eab_service)
    : repository_(repository), eab_service_(eab_service) {}

domain::NewAccountResponse AcmeAccountService::register_account(const domain::NewAccountRequest& request) const {
    if (!request.terms_of_service_agreed) {
        throw std::runtime_error("terms of service must be agreed");
    }
    if (!request.external_account_binding.has_value()) {
        throw std::runtime_error("external account binding is required");
    }

    if (const auto existing = repository_.find_by_public_jwk(request.account_public_jwk); existing.has_value()) {
        return {
            .account_id = existing->account_id,
            .location = "/acme/acct/" + existing->account_id,
            .created = false,
        };
    }

    const auto validation = eab_service_.validate(*request.external_account_binding, request.account_public_jwk);
    if (!validation.valid) {
        throw std::runtime_error(validation.error);
    }

    const domain::AcmeAccount account {
        .account_id = next_account_id(),
        .contacts = request.contacts,
        .account_public_jwk = request.account_public_jwk,
        .bound_client_id = validation.mapping.client_id,
        .ca_name = validation.mapping.ca,
    };

    const auto saved = repository_.save(account);
    return {
        .account_id = saved.account_id,
        .location = "/acme/acct/" + saved.account_id,
        .created = true,
    };
}

std::string AcmeAccountService::next_account_id() {
    return "acct-" + infrastructure::util::random_token(12);
}

}  // namespace acme::application
