#include "application/acme_workflow_service.h"

#include <stdexcept>

#include "infrastructure/util/json.h"
#include "infrastructure/util/random.h"
#include "infrastructure/util/sha256.h"

namespace acme::application {

AcmeWorkflowService::AcmeWorkflowService(
    const AcmeAccountRepository& account_repository,
    const EabMappingRepository& eab_repository,
    AcmeOrderRepository& order_repository,
    AcmeAuthorizationRepository& authorization_repository,
    AcmeCertificateRepository& certificate_repository,
    const CertificateAuthority& certificate_authority,
    const ChallengeValidator& challenge_validator,
    std::string base_url)
    : account_repository_(account_repository),
      eab_repository_(eab_repository),
      order_repository_(order_repository),
      authorization_repository_(authorization_repository),
      certificate_repository_(certificate_repository),
      certificate_authority_(certificate_authority),
      challenge_validator_(challenge_validator),
      base_url_(std::move(base_url)) {}

domain::AcmeOrder AcmeWorkflowService::create_order(
    const std::string& account_id,
    const std::vector<domain::Identifier>& identifiers) const {
    const auto account = account_repository_.find_by_id(account_id);
    if (!account.has_value()) {
        throw std::runtime_error("unknown ACME account");
    }
    if (identifiers.empty()) {
        throw std::runtime_error("order must contain at least one identifier");
    }

    domain::AcmeOrder order;
    order.order_id = next_id("order");
    order.account_id = account_id;
    order.status = "pending";
    order.expires_at = infrastructure::util::now_rfc3339();
    order.finalize_url = base_url_ + "/acme/order/" + order.order_id + "/finalize";
    order.identifiers = identifiers;

    for (const auto& identifier : identifiers) {
        domain::AcmeAuthorization authorization;
        authorization.authorization_id = next_id("authz");
        authorization.account_id = account_id;
        authorization.order_id = order.order_id;
        authorization.status = "pending";
        authorization.identifier_type = identifier.type;
        authorization.identifier_value = identifier.value;
        authorization.expires_at = infrastructure::util::now_rfc3339();

        domain::AcmeChallenge challenge;
        challenge.challenge_id = next_id("chall");
        challenge.type = "http-01";
        challenge.url = base_url_ + "/acme/challenge/" + challenge.challenge_id;
        challenge.token = infrastructure::util::random_token();

        authorization.challenges.push_back(challenge);
        authorization_repository_.save(authorization);
        order.authorization_ids.push_back(authorization.authorization_id);
    }

    return order_repository_.save(order);
}

std::optional<domain::AcmeAccount> AcmeWorkflowService::get_account(const std::string& account_id) const {
    return account_repository_.find_by_id(account_id);
}

std::vector<domain::AcmeOrder> AcmeWorkflowService::get_account_orders(const std::string& account_id) const {
    return order_repository_.find_by_account_id(account_id);
}

std::optional<domain::AcmeOrder> AcmeWorkflowService::get_order(const std::string& order_id) const {
    return order_repository_.find_by_id(order_id);
}

std::optional<domain::AcmeAuthorization> AcmeWorkflowService::get_authorization(const std::string& authorization_id) const {
    return authorization_repository_.find_by_id(authorization_id);
}

std::optional<domain::AcmeAuthorization> AcmeWorkflowService::get_authorization_by_challenge(
    const std::string& challenge_id) const {
    return authorization_repository_.find_by_challenge_id(challenge_id);
}

std::optional<domain::AcmeChallenge> AcmeWorkflowService::get_challenge(const std::string& challenge_id) const {
    const auto authorization = authorization_repository_.find_by_challenge_id(challenge_id);
    if (!authorization.has_value()) {
        return std::nullopt;
    }
    for (const auto& challenge : authorization->challenges) {
        if (challenge.challenge_id == challenge_id) {
            return challenge;
        }
    }
    return std::nullopt;
}

domain::AcmeChallenge AcmeWorkflowService::acknowledge_challenge(
    const std::string& challenge_id,
    const std::string& account_id,
    const std::optional<std::string>& supplied_key_authorization) const {
    const auto account = account_repository_.find_by_id(account_id);
    if (!account.has_value()) {
        throw std::runtime_error("unknown ACME account");
    }
    auto authorization = authorization_repository_.find_by_challenge_id(challenge_id);
    if (!authorization.has_value()) {
        throw std::runtime_error("unknown challenge");
    }
    if (authorization->account_id != account_id) {
        throw std::runtime_error("challenge does not belong to account");
    }

    for (auto& challenge : authorization->challenges) {
        if (challenge.challenge_id != challenge_id) {
            continue;
        }

        challenge.status = "processing";
        challenge.key_authorization = supplied_key_authorization.value_or(
            challenge.token + "." + jwk_thumbprint(account->account_public_jwk));

        const auto validation = challenge_validator_.validate_http_01(
            authorization->identifier_value,
            challenge.token,
            challenge.key_authorization);

        if (!validation.success) {
            challenge.status = "invalid";
            challenge.error_detail = validation.error;
            authorization->status = "invalid";
        } else {
            challenge.status = "valid";
            challenge.validated_at = infrastructure::util::now_rfc3339();
            challenge.error_detail.clear();
            authorization->status = "valid";
        }

        authorization_repository_.update(*authorization);

        auto order = order_repository_.find_by_id(authorization->order_id);
        if (!order.has_value()) {
            throw std::runtime_error("order missing for challenge");
        }

        bool all_valid = true;
        for (const auto& authorization_id : order->authorization_ids) {
            const auto item = authorization_repository_.find_by_id(authorization_id);
            if (!item.has_value() || item->status != "valid") {
                all_valid = false;
                break;
            }
        }
        if (all_valid) {
            order->status = "ready";
            order_repository_.update(*order);
        }

        return challenge;
    }

    throw std::runtime_error("challenge missing from authorization");
}

domain::AcmeOrder AcmeWorkflowService::finalize_order(
    const std::string& order_id,
    const std::string& account_id,
    const std::string& csr_pem) const {
    const auto account = account_repository_.find_by_id(account_id);
    if (!account.has_value()) {
        throw std::runtime_error("unknown ACME account");
    }

    auto order = order_repository_.find_by_id(order_id);
    if (!order.has_value()) {
        throw std::runtime_error("unknown order");
    }
    if (order->account_id != account_id) {
        throw std::runtime_error("order does not belong to account");
    }
    if (order->status != "ready" && order->status != "processing") {
        throw std::runtime_error("order is not ready for finalization");
    }

    const auto mapping = eab_repository_.find_by_client_id(account->bound_client_id);
    if (!mapping.has_value()) {
        throw std::runtime_error("no CA mapping for account");
    }

    order->status = "processing";
    order->csr_pem = csr_pem;
    order_repository_.update(*order);

    const auto result = certificate_authority_.issue_certificate(
        {
            .account_id = account_id,
            .csr_pem = csr_pem,
            .certificate_profile_name = "ServerTLS",
            .end_entity_profile_name = "AcmeIssued",
            .username = order->order_id,
            .enrollment_code = order->order_id,
            .include_chain = true,
            .identifiers = order->identifiers,
        },
        *mapping);

    if (!result.success) {
        order->status = "invalid";
        order_repository_.update(*order);
        throw std::runtime_error(result.error.empty() ? "certificate issuance failed" : result.error);
    }

    const auto certificate_id = next_id("cert");
    certificate_repository_.save({
        .certificate_id = certificate_id,
        .order_id = order->order_id,
        .pem_chain = result.certificate_pem_or_der,
        .leaf_pem = result.certificate_pem_or_der,
        .issued_at = infrastructure::util::now_rfc3339(),
        .serial_hex = "",
    });

    order->status = "valid";
    order->certificate_id = certificate_id;
    order->certificate_url = base_url_ + "/acme/certificate/" + certificate_id;
    return order_repository_.update(*order);
}

std::optional<domain::AcmeCertificate> AcmeWorkflowService::get_certificate(const std::string& certificate_id) const {
    return certificate_repository_.find_by_id(certificate_id);
}

std::string AcmeWorkflowService::next_id(const std::string& prefix) {
    return prefix + "-" + infrastructure::util::random_token(12);
}

std::string AcmeWorkflowService::jwk_thumbprint(const std::string& jwk) {
    using infrastructure::util::json::find_string;

    if (const auto kty = find_string(jwk, "kty"); kty == std::optional<std::string>{"EC"}) {
        const auto crv = find_string(jwk, "crv");
        const auto x = find_string(jwk, "x");
        const auto y = find_string(jwk, "y");
        if (crv.has_value() && x.has_value() && y.has_value()) {
            const std::string canonical =
                "{\"crv\":\"" + *crv + "\",\"kty\":\"EC\",\"x\":\"" + *x + "\",\"y\":\"" + *y + "\"}";
            return infrastructure::util::sha256_base64url(canonical);
        }
    }

    if (const auto kty = find_string(jwk, "kty"); kty == std::optional<std::string>{"RSA"}) {
        const auto e = find_string(jwk, "e");
        const auto n = find_string(jwk, "n");
        if (e.has_value() && n.has_value()) {
            const std::string canonical =
                "{\"e\":\"" + *e + "\",\"kty\":\"RSA\",\"n\":\"" + *n + "\"}";
            return infrastructure::util::sha256_base64url(canonical);
        }
    }

    return infrastructure::util::sha256_base64url(jwk);
}

}  // namespace acme::application
