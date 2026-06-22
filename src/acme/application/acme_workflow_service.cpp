#include "acme/application/acme_workflow_service.h"

#include <iostream>
#include <map>
#include <stdexcept>
#include "acme/infrastructure/http01_webroot_publisher.h"
#include "acme/infrastructure/util/json.h"
#include "acme/infrastructure/util/random.h"
#include "acme/infrastructure/util/sha256.h"

namespace acme::application
{

    AcmeWorkflowService::AcmeWorkflowService(
        const AcmeAccountRepository &account_repository,
        const EabMappingRepository &eab_repository,
        AcmeOrderRepository &order_repository,
        AcmeAuthorizationRepository &authorization_repository,
        AcmeCertificateRepository &certificate_repository,
        const CertificateAuthority &certificate_authority,
        const ChallengeValidator &challenge_validator,
        std::string http01_challenge_webroot,
        std::string base_url)
        : account_repository_(account_repository),
          eab_repository_(eab_repository),
          order_repository_(order_repository),
          authorization_repository_(authorization_repository),
          certificate_repository_(certificate_repository),
          certificate_authority_(certificate_authority),
          challenge_validator_(challenge_validator),
          http01_challenge_webroot_(std::move(http01_challenge_webroot)),
          base_url_(std::move(base_url)) {}

    domain::AcmeOrder AcmeWorkflowService::create_order(
        const std::string &account_id,
        const std::vector<domain::Identifier> &identifiers) const
    {
        const auto account = account_repository_.find_by_id(account_id);
        if (!account.has_value())
        {
            throw std::runtime_error("unknown ACME account");
        }
        if (identifiers.empty())
        {
            throw std::runtime_error("order must contain at least one identifier");
        }
        const auto mapping = eab_repository_.find_by_client_id(account->bound_client_id);
        if (!mapping.has_value())
        {
            throw std::runtime_error("no CA mapping for account");
        }
        std::cout << "[acme] newOrder account=" << account_id
                  << " bound_client_id=" << account->bound_client_id
                  << " ca=" << mapping->ca
                  << " credentials_id=" << mapping->credentials_id << "\n";

        domain::AcmeOrder order;
        order.order_id = next_id("order");
        order.account_id = account_id;
        order.status = "pending";
        order.expires_at = infrastructure::util::now_rfc3339();
        order.finalize_url = base_url_ + "/acme/order/" + order.order_id + "/finalize";
        order.identifiers = identifiers;

        if (certificate_authority_.supports_external_authorizations(*mapping))
        {
            std::cout << "[acme] routing newOrder to upstream ACME ca=" << mapping->ca
                      << " credentials_id=" << mapping->credentials_id << "\n";
            const auto upstream = certificate_authority_.create_order(account_id, identifiers, *mapping);
            if (!upstream.success)
            {
                throw std::runtime_error(upstream.error.empty() ? "upstream ACME order creation failed" : upstream.error);
            }
            order.status = upstream.status;
            order.upstream_url = upstream.upstream_order_url;
            order.upstream_finalize_url = upstream.upstream_finalize_url;
            order.upstream_certificate_url = upstream.upstream_certificate_url;
            std::cout << "[acme] upstream authz count=" << upstream.authorizations.size() << "\n";
            for (const auto &upstream_authz : upstream.authorizations)
            {
                domain::AcmeAuthorization authorization = upstream_authz;
                authorization.authorization_id = next_id("authz");
                authorization.account_id = account_id;
                authorization.order_id = order.order_id;
                if (authorization.expires_at.empty())
                {
                    authorization.expires_at = infrastructure::util::now_rfc3339();
                }
                for (auto &challenge : authorization.challenges)
                {
                    challenge.challenge_id = next_id("chall");
                    challenge.url = base_url_ + "/acme/challenge/" + challenge.challenge_id;
                    if (mapping.has_value() &&
                        certificate_authority_.supports_http01_challenge_proxy(*mapping))
                    {
                        std::cout << "[acme] upstream http-01 token=" << challenge.token
                                  << " key_authorization=" << challenge.key_authorization
                                  << " http01_proxy=" << base_url_ << "/acme/http01/" << challenge.token
                                  << "\n";
                    }
                    else
                    {
                        std::cout << "[acme] upstream http-01 token=" << challenge.token
                                  << " key_authorization=" << challenge.key_authorization
                                  << "\n";
                    }
                }
                authorization_repository_.save(authorization);
                order.authorization_ids.push_back(authorization.authorization_id);
            }
            return order_repository_.save(order);
        }

        for (const auto &identifier : identifiers)
        {
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

    std::optional<domain::AcmeAccount> AcmeWorkflowService::get_account(const std::string &account_id) const
    {
        return account_repository_.find_by_id(account_id);
    }

    std::vector<domain::AcmeOrder> AcmeWorkflowService::get_account_orders(const std::string &account_id) const
    {
        return order_repository_.find_by_account_id(account_id);
    }

    std::optional<domain::AcmeOrder> AcmeWorkflowService::get_order(const std::string &order_id) const
    {
        return order_repository_.find_by_id(order_id);
    }

    std::optional<domain::AcmeAuthorization>
    AcmeWorkflowService::get_authorization(
        const std::string &authorization_id) const
    {
        auto authorization =
            authorization_repository_
                .find_by_id(
                    authorization_id);

        if (!authorization.has_value())
        {
            return std::nullopt;
        }

        if (!authorization->upstream_url.empty())
        {
            auto account =
                account_repository_
                    .find_by_id(
                        authorization->account_id);

            if (account.has_value())
            {
                auto mapping =
                    eab_repository_
                        .find_by_client_id(
                            account->bound_client_id);

                if (mapping.has_value())
                {
                    auto upstream =
                        certificate_authority_
                            .get_authorization(
                                authorization->upstream_url,
                                *mapping);

                    if (upstream.has_value())
                    {
                        const auto local_status = authorization->status;
                        std::map<std::string, std::pair<std::string, std::string>> local_challenges;
                        for (const auto &challenge : authorization->challenges)
                        {
                            local_challenges[challenge.token] = {
                                challenge.status,
                                challenge.error_detail,
                            };
                        }

                        authorization->status = upstream->status;
                        if (local_status == "invalid")
                        {
                            authorization->status = "invalid";
                        }

                        std::cout << "[acme] poll upstream authz url=" << authorization->upstream_url
                                  << " upstream_status=" << upstream->status
                                  << " local_status=" << local_status << "\n";

                        for (auto &challenge : authorization->challenges)
                        {
                            for (const auto &upstream_challenge : upstream->challenges)
                            {
                                if (challenge.upstream_url == upstream_challenge.upstream_url ||
                                    (!challenge.token.empty() &&
                                     challenge.token == upstream_challenge.token))
                                {
                                    const auto local = local_challenges.find(challenge.token);
                                    challenge.status = upstream_challenge.status;
                                    if (!upstream_challenge.error_detail.empty())
                                    {
                                        challenge.error_detail = upstream_challenge.error_detail;
                                    }
                                    if (local != local_challenges.end() &&
                                        local->second.first == "invalid" &&
                                        challenge.status == "pending")
                                    {
                                        challenge.status = "invalid";
                                        if (!local->second.second.empty())
                                        {
                                            challenge.error_detail = local->second.second;
                                        }
                                    }
                                    std::cout << "[acme] poll challenge token=" << challenge.token
                                              << " status=" << challenge.status;
                                    if (!challenge.error_detail.empty())
                                    {
                                        std::cout << " error=" << challenge.error_detail;
                                    }
                                    std::cout << "\n";
                                    if (challenge.status == "valid" &&
                                        challenge.validated_at.empty())
                                    {
                                        challenge.validated_at =
                                            infrastructure::util::now_rfc3339();
                                    }
                                    break;
                                }
                            }
                        }

                        if (authorization->status == "valid")
                        {
                            for (auto &challenge : authorization->challenges)
                            {
                                if (challenge.status != "valid")
                                {
                                    challenge.status = "valid";
                                    if (challenge.validated_at.empty())
                                    {
                                        challenge.validated_at =
                                            infrastructure::util::now_rfc3339();
                                    }
                                }
                            }
                        }

                        authorization_repository_.update(*authorization);

                        auto order =
                            order_repository_.find_by_id(
                                authorization->order_id);
                        if (order.has_value())
                        {
                            bool all_valid = true;
                            for (const auto &authorization_id :
                                 order->authorization_ids)
                            {
                                const auto item =
                                    authorization_repository_.find_by_id(
                                        authorization_id);
                                if (!item.has_value() ||
                                    item->status != "valid")
                                {
                                    all_valid = false;
                                    break;
                                }
                            }
                            if (all_valid && order->status == "pending")
                            {
                                order->status = "ready";
                                order_repository_.update(*order);
                            }
                        }
                    }
                }
            }
        }

        return authorization;
    }
    std::optional<domain::AcmeAuthorization> AcmeWorkflowService::get_authorization_by_challenge(
        const std::string &challenge_id) const
    {
        return authorization_repository_.find_by_challenge_id(challenge_id);
    }

    std::optional<domain::AcmeChallenge> AcmeWorkflowService::get_challenge(const std::string &challenge_id) const
    {
        const auto authorization = authorization_repository_.find_by_challenge_id(challenge_id);
        if (!authorization.has_value())
        {
            return std::nullopt;
        }
        for (const auto &challenge : authorization->challenges)
        {
            if (challenge.challenge_id == challenge_id)
            {
                return challenge;
            }
        }
        return std::nullopt;
    }

    std::optional<std::string> AcmeWorkflowService::get_http01_challenge_response(
        const std::string &token) const
    {
        const auto authorization = authorization_repository_.find_by_challenge_token(token);
        if (!authorization.has_value())
        {
            return std::nullopt;
        }

        const auto account = account_repository_.find_by_id(authorization->account_id);
        if (!account.has_value())
        {
            return std::nullopt;
        }

        const auto mapping = eab_repository_.find_by_client_id(account->bound_client_id);
        if (!mapping.has_value() ||
            !certificate_authority_.supports_http01_challenge_proxy(*mapping))
        {
            return std::nullopt;
        }

        for (const auto &challenge : authorization->challenges)
        {
            if (challenge.token == token &&
                challenge.type == "http-01" &&
                !challenge.key_authorization.empty())
            {
                return challenge.key_authorization;
            }
        }

        return std::nullopt;
    }

    domain::AcmeChallenge AcmeWorkflowService::acknowledge_challenge(
        const std::string &challenge_id,
        const std::string &account_id,
        const std::optional<std::string> &supplied_key_authorization) const
    {
        const auto account = account_repository_.find_by_id(account_id);
        if (!account.has_value())
        {
            throw std::runtime_error("unknown ACME account");
        }
        auto authorization = authorization_repository_.find_by_challenge_id(challenge_id);
        if (!authorization.has_value())
        {
            throw std::runtime_error("unknown challenge");
        }
        if (authorization->account_id != account_id)
        {
            throw std::runtime_error("challenge does not belong to account");
        }

        for (auto &challenge : authorization->challenges)
        {
            if (challenge.challenge_id != challenge_id)
            {
                continue;
            }

            const bool upstream_challenge = !challenge.upstream_url.empty();
            challenge.status = "processing";
            const auto mapping = eab_repository_.find_by_client_id(
                account->bound_client_id);

            if (upstream_challenge)
            {
                if (challenge.key_authorization.empty())
                {
                    throw std::runtime_error("upstream challenge is missing key authorization");
                }

                std::cout << "[acme] challenge ack challenge_id=" << challenge_id
                          << " domain=" << authorization->identifier_value
                          << " token=" << challenge.token
                          << " expected_key_authorization=" << challenge.key_authorization
                          << "\n";

                const bool le_http01_proxy =
                    mapping.has_value() &&
                    certificate_authority_.supports_http01_challenge_proxy(*mapping);

                if (le_http01_proxy)
                {
                    std::cout << "[acme] http-01 proxy token=" << challenge.token
                              << " url=" << base_url_ << "/acme/http01/" << challenge.token
                              << " (nginx: proxy /.well-known/acme-challenge/ to this path)"
                              << "\n";
                    const auto precheck = challenge_validator_.validate_http_01(
                        authorization->identifier_value,
                        challenge.token,
                        challenge.key_authorization);
                    if (precheck.success)
                    {
                        std::cout << "[acme] http-01 domain pre-check ok for "
                                  << authorization->identifier_value << "\n";
                    }
                    else
                    {
                        std::cout << "[acme] http-01 domain pre-check failed: " << precheck.error
                                  << " — fix nginx to proxy /.well-known/acme-challenge/ to "
                                  << base_url_ << "/acme/http01/ (remove certbot location= blocks)"
                                  << "\n";
                    }
                }
                else if (!http01_challenge_webroot_.empty())
                {
                    const infrastructure::Http01WebrootPublisher webroot_publisher(
                        http01_challenge_webroot_);
                    const auto publish_result = webroot_publisher.publish(
                        challenge.token,
                        challenge.key_authorization);
                    if (!publish_result.success)
                    {
                        challenge.status = "invalid";
                        challenge.error_detail = publish_result.error;
                        authorization->status = "invalid";
                        std::cout << "[acme] http-01 webroot publish failed token=" << challenge.token
                                  << " reason=" << challenge.error_detail << "\n";
                        authorization_repository_.update(*authorization);
                        return challenge;
                    }
                    std::cout << "[acme] http-01 webroot published token=" << challenge.token << "\n";
                }

                std::cout << "[acme] forwarding challenge ack to upstream url="
                          << challenge.upstream_url << "\n";

                const auto upstream_validation =
                    mapping.has_value()
                        ? certificate_authority_.acknowledge_challenge(
                              challenge.upstream_url,
                              *mapping)
                        : domain::CertificateIssueResult{.error = "no CA mapping for account"};

                if (!upstream_validation.success)
                {
                    challenge.status = "invalid";
                    challenge.error_detail = upstream_validation.error;
                    authorization->status = "invalid";
                    std::cout << "[acme] upstream challenge ack failed: " << upstream_validation.error
                              << "\n";
                }
                else
                {
                    challenge.status = "processing";
                    authorization->status = "pending";
                    std::cout << "[acme] upstream challenge ack accepted token=" << challenge.token
                              << "\n";
                }
            }
            else
            {
                challenge.key_authorization = supplied_key_authorization.value_or(
                    challenge.token + "." + jwk_thumbprint(account->account_public_jwk));

                const auto validation = challenge_validator_.validate_http_01(
                    authorization->identifier_value,
                    challenge.token,
                    challenge.key_authorization);

                if (!validation.success)
                {
                    challenge.status = "invalid";
                    challenge.error_detail = validation.error;
                    authorization->status = "invalid";
                }
                else
                {
                    challenge.status = "valid";
                    challenge.validated_at = infrastructure::util::now_rfc3339();
                    authorization->status = "valid";
                }
            }

            authorization_repository_.update(*authorization);

            auto order = order_repository_.find_by_id(authorization->order_id);
            if (!order.has_value())
            {
                throw std::runtime_error("order missing for challenge");
            }

            bool all_valid = true;
            for (const auto &authorization_id : order->authorization_ids)
            {
                const auto item = authorization_repository_.find_by_id(authorization_id);
                if (!item.has_value() || item->status != "valid")
                {
                    all_valid = false;
                    break;
                }
            }

            if (all_valid)
            {
                bool upstream_ready =
                    true;

                for (const auto &
                         authorization_id :
                     order->authorization_ids)
                {
                    auto auth =
                        authorization_repository_
                            .find_by_id(
                                authorization_id);

                    if (!auth.has_value() ||
                        auth->status != "valid")
                    {
                        upstream_ready = false;
                        break;
                    }
                }

                if (upstream_ready)
                {
                    order->status = "ready";
                }
                order_repository_.update(*order);
            }
            return challenge;
        }

        throw std::runtime_error("challenge missing from authorization");
    }

    domain::AcmeOrder AcmeWorkflowService::finalize_order(
        const std::string &order_id,
        const std::string &account_id,
        const std::string &csr_pem) const
    {
        const auto account = account_repository_.find_by_id(account_id);
        if (!account.has_value())
        {
            throw std::runtime_error("unknown ACME account");
        }

        auto order = order_repository_.find_by_id(order_id);
        if (!order.has_value())
        {
            throw std::runtime_error("unknown order");
        }
        if (order->account_id != account_id)
        {
            throw std::runtime_error("order does not belong to account");
        }
        if (order->status != "ready" && order->status != "processing")
        {
            throw std::runtime_error("order is not ready for finalization");
        }

        const auto mapping = eab_repository_.find_by_client_id(account->bound_client_id);
        if (!mapping.has_value())
        {
            throw std::runtime_error("no CA mapping for account");
        }
        std::cout << "[acme] finalize order=" << order->order_id
                  << " account=" << account_id
                  << " bound_client_id=" << account->bound_client_id
                  << " ca=" << mapping->ca
                  << " credentials_id=" << mapping->credentials_id
                  << " upstream_order_url=" << order->upstream_url << "\n";

        order->status = "processing";
        order->csr_pem = csr_pem;
        order_repository_.update(*order);

        const auto result = certificate_authority_.issue_certificate(
            {
                .account_id = account_id,
                .csr_pem = csr_pem,
                .certificate_profile_name = "ServerTLS",
                .end_entity_profile_name = "AcmeIssued",
                .username = order->upstream_url.empty() ? order->order_id : order->upstream_url,
                .enrollment_code = order->upstream_finalize_url.empty() ? order->order_id : order->upstream_finalize_url,
                .include_chain = true,
                .identifiers = order->identifiers,
            },
            *mapping);

        if (!result.success)
        {
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

    std::optional<domain::AcmeCertificate> AcmeWorkflowService::get_certificate(const std::string &certificate_id) const
    {
        return certificate_repository_.find_by_id(certificate_id);
    }

    std::string AcmeWorkflowService::next_id(const std::string &prefix)
    {
        return prefix + "-" + infrastructure::util::random_token(12);
    }

    std::string AcmeWorkflowService::jwk_thumbprint(const std::string &jwk)
    {
        using infrastructure::util::json::find_string;

        if (const auto kty = find_string(jwk, "kty"); kty == std::optional<std::string>{"EC"})
        {
            const auto crv = find_string(jwk, "crv");
            const auto x = find_string(jwk, "x");
            const auto y = find_string(jwk, "y");
            if (crv.has_value() && x.has_value() && y.has_value())
            {
                const std::string canonical =
                    "{\"crv\":\"" + *crv + "\",\"kty\":\"EC\",\"x\":\"" + *x + "\",\"y\":\"" + *y + "\"}";
                return infrastructure::util::sha256_base64url(canonical);
            }
        }

        if (const auto kty = find_string(jwk, "kty"); kty == std::optional<std::string>{"RSA"})
        {
            const auto e = find_string(jwk, "e");
            const auto n = find_string(jwk, "n");
            if (e.has_value() && n.has_value())
            {
                const std::string canonical =
                    "{\"e\":\"" + *e + "\",\"kty\":\"RSA\",\"n\":\"" + *n + "\"}";
                return infrastructure::util::sha256_base64url(canonical);
            }
        }

        return infrastructure::util::sha256_base64url(jwk);
    }

} // namespace acme::application
