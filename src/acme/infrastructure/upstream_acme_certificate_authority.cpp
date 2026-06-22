#include "acme/infrastructure/upstream_acme_certificate_authority.h"
#include "acme/domain/ca_constants.h"
#include <iostream>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <regex>
#include <sstream>
#include <stdexcept>

#include "acme/infrastructure/util/base64url.h"
#include "acme/infrastructure/util/file_store.h"
#include "acme/infrastructure/util/hmac_sha256.h"
#include "acme/infrastructure/util/json.h"
#include "acme/infrastructure/util/random.h"
#include "acme/infrastructure/util/sha256.h"
#include <nlohmann/json.hpp>

namespace acme::infrastructure
{
    namespace
    {
        struct Directory
        {
            std::string new_nonce;
            std::string new_account;
            std::string new_order;
        };

        std::string header_value(const HttpResponse &response, const std::string &name)
        {
            const auto found = response.headers.find(name);
            return found == response.headers.end() ? "" : found->second;
        }

        std::string bn_b64(const BIGNUM *value)
        {
            const auto size = BN_num_bytes(value);
            std::string bytes(static_cast<std::size_t>(size), '\0');
            BN_bn2bin(value, reinterpret_cast<unsigned char *>(bytes.data()));
            return util::base64url_encode(bytes);
        }

        std::string generate_rsa_private_key_pem()
        {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("failed to initialize upstream ACME account key generation");
            }

            EVP_PKEY *key = nullptr;
            if (EVP_PKEY_keygen(ctx, &key) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("failed to generate upstream ACME account key");
            }
            EVP_PKEY_CTX_free(ctx);

            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
            BUF_MEM *buffer = nullptr;
            BIO_get_mem_ptr(bio, &buffer);
            std::string pem(buffer->data, buffer->length);
            BIO_free(bio);
            EVP_PKEY_free(key);
            return pem;
        }

        EVP_PKEY *read_private_key(const std::string &pem)
        {
            BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
            EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (key == nullptr)
            {
                throw std::runtime_error("invalid upstream ACME account private key PEM");
            }
            return key;
        }

        std::string jwk_from_private_key(const std::string &pem)
        {
            EVP_PKEY *key = read_private_key(pem);
            std::string jwk;
            if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA)
            {
                RSA *rsa = EVP_PKEY_get1_RSA(key);
                const BIGNUM *n = nullptr;
                const BIGNUM *e = nullptr;
                RSA_get0_key(rsa, &n, &e, nullptr);
                jwk = "{\"e\":\"" + bn_b64(e) + "\",\"kty\":\"RSA\",\"n\":\"" + bn_b64(n) + "\"}";
                RSA_free(rsa);
            }
            EVP_PKEY_free(key);
            if (jwk.empty())
            {
                throw std::runtime_error("only RSA upstream ACME account keys are currently supported");
            }
            return jwk;
        }

        std::string sign_rs256(const std::string &pem, const std::string &data)
        {
            EVP_PKEY *key = read_private_key(pem);
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) <= 0 ||
                EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
            {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(key);
                throw std::runtime_error("failed to initialize upstream ACME JWS signature");
            }
            std::size_t signature_size = 0;
            EVP_DigestSignFinal(ctx, nullptr, &signature_size);
            std::string signature(signature_size, '\0');
            if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char *>(signature.data()), &signature_size) <= 0)
            {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(key);
                throw std::runtime_error("failed to sign upstream ACME JWS");
            }
            signature.resize(signature_size);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            return util::base64url_encode(signature);
        }

        std::string csr_der_b64url(const std::string &pem)
        {
            BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
            X509_REQ *request = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (request == nullptr)
            {
                throw std::runtime_error("invalid CSR PEM");
            }
            int length = i2d_X509_REQ(request, nullptr);
            std::string der(static_cast<std::size_t>(length), '\0');
            unsigned char *cursor = reinterpret_cast<unsigned char *>(der.data());
            i2d_X509_REQ(request, &cursor);
            X509_REQ_free(request);
            return util::base64url_encode(der);
        }

        std::string signed_jws(
            const domain::CaCredential &credential,
            const std::string &url,
            const std::string &nonce,
            const std::string &payload_json,
            bool use_kid)
        {
            const auto jwk = jwk_from_private_key(credential.account_key_pem);
            std::string protected_json = "{\"alg\":\"RS256\",";
            if (use_kid)
            {
                protected_json += "\"kid\":\"" + util::json::escape(credential.account_url) + "\",";
            }
            else
            {
                protected_json += "\"jwk\":" + jwk + ",";
            }
            protected_json += "\"nonce\":\"" + util::json::escape(nonce) + "\",\"url\":\"" + util::json::escape(url) + "\"}";

            const auto protected_b64 = util::base64url_encode(protected_json);
            const auto payload_b64 = payload_json.empty() ? std::string{} : util::base64url_encode(payload_json);
            const auto signature = sign_rs256(credential.account_key_pem, protected_b64 + "." + payload_b64);
            return "{\"protected\":\"" + protected_b64 + "\",\"payload\":\"" + payload_b64 + "\",\"signature\":\"" + signature + "\"}";
        }

        std::string eab_jws(const domain::CaCredential &credential, const std::string &new_account_url)
        {
            if (credential.eab_kid.empty() || credential.eab_hmac_key.empty())
            {
                return "";
            }
            const auto jwk = jwk_from_private_key(credential.account_key_pem);
            const auto protected_json = "{\"alg\":\"HS256\",\"kid\":\"" + util::json::escape(credential.eab_kid) +
                                        "\",\"url\":\"" + util::json::escape(new_account_url) + "\"}";
            const auto protected_b64 = util::base64url_encode(protected_json);
            const auto payload_b64 = util::base64url_encode(jwk);
            std::string hmac_key = credential.eab_hmac_key;
            if (hmac_key.find_first_of("-_") != std::string::npos || hmac_key.find('=') == std::string::npos)
            {
                const auto decoded = util::base64url_decode(hmac_key);
                if (!decoded.empty())
                {
                    hmac_key = decoded;
                }
            }
            const auto signature = util::hmac_sha256_base64url(hmac_key, protected_b64 + "." + payload_b64);
            return "{\"protected\":\"" + protected_b64 + "\",\"payload\":\"" + payload_b64 + "\",\"signature\":\"" + signature + "\"}";
        }

        std::string identifiers_json(const std::vector<domain::Identifier> &identifiers)
        {
            std::ostringstream output;
            output << "{\"identifiers\":[";
            for (std::size_t index = 0; index < identifiers.size(); ++index)
            {
                if (index > 0)
                {
                    output << ",";
                }
                output << "{\"type\":\"" << util::json::escape(identifiers[index].type) << "\",\"value\":\""
                       << util::json::escape(identifiers[index].value) << "\"}";
            }
            output << "]}";
            return output.str();
        }

        std::vector<std::string> find_url_array(
            const std::string &json_text,
            const std::string &key)
        {
            std::vector<std::string> result;

            auto j = nlohmann::json::parse(json_text);

            if (!j.contains(key))
                return result;

            for (const auto &item : j[key])
            {
                result.push_back(item.get<std::string>());
            }

            return result;
        }
        std::string jwk_thumbprint_from_json(const std::string &jwk)
        {
            if (const auto kty = util::json::find_string(jwk, "kty"); kty == std::optional<std::string>{"EC"})
            {
                const auto crv = util::json::find_string(jwk, "crv");
                const auto x = util::json::find_string(jwk, "x");
                const auto y = util::json::find_string(jwk, "y");
                if (crv.has_value() && x.has_value() && y.has_value())
                {
                    const std::string canonical =
                        "{\"crv\":\"" + *crv + "\",\"kty\":\"EC\",\"x\":\"" + *x + "\",\"y\":\"" + *y + "\"}";
                    return util::sha256_base64url(canonical);
                }
            }

            if (const auto kty = util::json::find_string(jwk, "kty"); kty == std::optional<std::string>{"RSA"})
            {
                const auto e = util::json::find_string(jwk, "e");
                const auto n = util::json::find_string(jwk, "n");
                if (e.has_value() && n.has_value())
                {
                    const std::string canonical =
                        "{\"e\":\"" + *e + "\",\"kty\":\"RSA\",\"n\":\"" + *n + "\"}";
                    return util::sha256_base64url(canonical);
                }
            }

            return util::sha256_base64url(jwk);
        }

        std::vector<domain::AcmeChallenge> parse_http01_challenges(const std::string &json, const std::string &account_jwk)
        {
            std::vector<domain::AcmeChallenge> challenges;

            const std::regex object_pattern(
                "\\{[^{}]*\"type\"\\s*:\\s*\"http-01\"[^{}]*\\}");

            auto begin =
                std::sregex_iterator(
                    json.begin(),
                    json.end(),
                    object_pattern);

            auto end = std::sregex_iterator();

            const auto account_thumbprint = jwk_thumbprint_from_json(account_jwk);

            for (auto it = begin; it != end; ++it)
            {
                const auto object = it->str();

                auto url =
                    util::json::find_string(
                        object,
                        "url");

                auto token =
                    util::json::find_string(
                        object,
                        "token");

                auto status =
                    util::json::find_string(
                        object,
                        "status");

                std::string error_detail;
                if (const auto error_object = util::json::find_object(object, "error");
                    error_object.has_value())
                {
                    error_detail = util::json::find_string(*error_object, "detail").value_or("");
                    if (error_detail.empty())
                    {
                        error_detail = util::json::find_string(*error_object, "type").value_or("");
                    }
                }

                if (url.has_value() &&
                    token.has_value())
                {
                    challenges.push_back({
                        .type = "http-01",
                        .status = status.value_or("pending"),
                        .token = *token,
                        .error_detail = error_detail,
                        .key_authorization = account_thumbprint.empty()
                                                 ? ""
                                                 : *token + "." + account_thumbprint,
                        .upstream_url = *url,
                    });
                }
            }

            return challenges;
        }

    } // namespace

    UpstreamAcmeCertificateAuthority::UpstreamAcmeCertificateAuthority(
        std::shared_ptr<PostgresCaCredentialRepository> credentials,
        std::string working_dir)
        : credentials_(std::move(credentials)), working_dir_(std::move(working_dir)) {}

    std::string UpstreamAcmeCertificateAuthority::authority_name() const
    {
        return "*";
    }

    domain::CaCredential UpstreamAcmeCertificateAuthority::credential_for(const domain::EabMapping &mapping) const
    {
        if (!credentials_)
        {
            throw std::runtime_error("upstream ACME credentials repository is not configured");
        }
        auto credential = credentials_->find_by_id(mapping.credentials_id);
        if (!credential.has_value())
        {
            throw std::runtime_error("unknown CA credentials_id: " + mapping.credentials_id);
        }
        if (credential->ca_name != mapping.ca)
        {
            throw std::runtime_error("CA credential does not match EAB mapping CA");
        }
        if (credential->account_key_pem.empty())
        {
            credential->account_key_pem = generate_rsa_private_key_pem();
            credentials_->save(*credential);
        }
        return *credential;
    }

    bool UpstreamAcmeCertificateAuthority::supports_external_authorizations(const domain::EabMapping &mapping) const
    {
        if (!credentials_)
        {
            return false;
        }
        const auto credential = credentials_->find_by_id(mapping.credentials_id);
        return credential.has_value() && credential->ca_type == "acme";
    }

    std::optional<domain::AcmeAuthorization>
    UpstreamAcmeCertificateAuthority::get_authorization(
        const std::string &authorization_url,
        const domain::EabMapping &mapping) const
    {
        try
        {
            auto credential = credential_for(mapping);

            auto directory_response = http_.execute({
                .method = "GET",
                .url = credential.directory_url,
                .insecure_skip_tls_verify =
                    credential.insecure_skip_tls_verify,
            });
            const auto new_nonce =
                util::json::find_string(
                    directory_response.body,
                    "newNonce")
                    .value_or("");

            HttpRequest nonce_request{
                .method = "HEAD",
                .url = new_nonce,
                .headers = {},
                .body = "",
                .client_pkcs12_bundle = std::nullopt,
                .client_pkcs12_password = std::nullopt,
                .insecure_skip_tls_verify =
                    credential.insecure_skip_tls_verify,
            };

            auto nonce_response =
                http_.execute(nonce_request);

            const auto nonce =
                header_value(
                    nonce_response,
                    "replay-nonce");

            HttpRequest authz_request{
                .method = "POST",
                .url = authorization_url,
                .headers = {
                    {"Content-Type",
                     "application/jose+json"}},
                .body = signed_jws(credential, authorization_url, nonce, "", true),
                .client_pkcs12_bundle = std::nullopt,
                .client_pkcs12_password = std::nullopt,
                .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
            };

            auto response =
                http_.execute(authz_request);

            if (response.status_code < 200 ||
                response.status_code >= 300)
            {
                std::cout << "[acme] upstream authz poll failed status="
                          << response.status_code << " body=" << response.body << "\n";
                return std::nullopt;
            }

            std::cout << "[acme] upstream authz poll url=" << authorization_url
                      << " status="
                      << util::json::find_string(response.body, "status").value_or("pending")
                      << "\n";

            auto identifier =
                util::json::find_object(
                    response.body,
                    "identifier")
                    .value_or("{}");

            const auto account_jwk =
                jwk_from_private_key(
                    credential.account_key_pem);

            return domain::AcmeAuthorization{
                .status =
                    util::json::find_string(
                        response.body,
                        "status")
                        .value_or("pending"),

                .identifier_type =
                    util::json::find_string(
                        identifier,
                        "type")
                        .value_or("dns"),

                .identifier_value =
                    util::json::find_string(
                        identifier,
                        "value")
                        .value_or(""),

                .expires_at =
                    util::json::find_string(
                        response.body,
                        "expires")
                        .value_or(""),

                .challenges =
                    parse_http01_challenges(
                        response.body,
                        account_jwk),

                .upstream_url =
                    authorization_url,
            };
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    bool UpstreamAcmeCertificateAuthority::client_account_matches_upstream(
        const std::string &client_account_jwk,
        const domain::EabMapping &mapping) const
    {
        try
        {
            const auto credential = credential_for(mapping);
            const auto upstream_jwk = jwk_from_private_key(credential.account_key_pem);
            return jwk_thumbprint_from_json(client_account_jwk) ==
                   jwk_thumbprint_from_json(upstream_jwk);
        }
        catch (...)
        {
            return false;
        }
    }

    bool UpstreamAcmeCertificateAuthority::supports_http01_challenge_proxy(
        const domain::EabMapping &mapping) const
    {
        if (!supports_external_authorizations(mapping))
        {
            return false;
        }
        try
        {
            const auto credential = credential_for(mapping);
            return domain::credential_supports_http01_proxy(credential);
        }
        catch (...)
        {
            return false;
        }
    }

    domain::AcmeRelayOrderResult UpstreamAcmeCertificateAuthority::create_order(
        const std::string &account_id,
        const std::vector<domain::Identifier> &identifiers,
        const domain::EabMapping &mapping) const
    {
        (void)account_id;
        try
        {
            std::cout << "[acme] inside upstream creating upstream order ca=" << mapping.ca
                      << " credentials_id=" << mapping.credentials_id << std::endl;

            auto credential = credential_for(mapping);
            const auto directory_response = http_.execute({.method = "GET", .url = credential.directory_url, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            if (directory_response.status_code < 200 || directory_response.status_code >= 300)
            {
                return {.error = "failed to load upstream ACME directory: " + directory_response.body};
            }

            std::cout << "\n========== RAW DIRECTORY RESPONSE ==========\n";
            std::cout << directory_response.body << "\n";
            std::cout << "========================================\n";

            Directory directory{
                .new_nonce = util::json::find_string(directory_response.body, "newNonce").value_or(""),
                .new_account = util::json::find_string(directory_response.body, "newAccount").value_or(""),
                .new_order = util::json::find_string(directory_response.body, "newOrder").value_or(""),
            };
            if (directory.new_nonce.empty() || directory.new_account.empty() || directory.new_order.empty())
            {
                return {.error = "upstream ACME directory is missing required endpoints"};
            }

            auto nonce_response = http_.execute({.method = "HEAD", .url = directory.new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            auto nonce = header_value(nonce_response, "replay-nonce");
            if (nonce.empty())
            {
                return {.error = "upstream ACME newNonce did not return Replay-Nonce"};
            }

            if (credential.account_url.empty())
            {
                auto payload = std::string("{\"termsOfServiceAgreed\":") + (credential.terms_of_service_agreed ? "true" : "false");
                const auto binding = eab_jws(credential, directory.new_account);
                if (!binding.empty())
                {
                    payload += ",\"externalAccountBinding\":" + binding;
                }
                payload += "}";
                auto account_response = http_.execute({
                    .method = "POST",
                    .url = directory.new_account,
                    .headers = {{"Content-Type", "application/jose+json"}},
                    .body = signed_jws(credential, directory.new_account, nonce, payload, false),
                    .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
                });
                std::cout << "NEW ACCOUNT RESPONSE:\n"
                          << account_response.body << "\n";
                std::cout << "NEW ACCOUNT RESPONSE Status Code:\n"
                          << account_response.status_code << "\n";
                if (account_response.status_code < 200 || account_response.status_code >= 300)
                {
                    return {.error = "upstream ACME newAccount failed: " + account_response.body};
                }
                credential.account_url = header_value(account_response, "location");
                if (credential.account_url.empty())
                {
                    return {.error = "upstream ACME newAccount did not return Location"};
                }
                credentials_->save(credential);
                nonce = header_value(account_response, "replay-nonce");
            }

            if (nonce.empty())
            {
                nonce_response = http_.execute({.method = "HEAD", .url = directory.new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
                nonce = header_value(nonce_response, "replay-nonce");
            }

            std::cout << "Sending POST Request with nonce: " << nonce << "\n";

            const auto order_response = http_.execute({
                .method = "POST",
                .url = directory.new_order,
                .headers = {{"Content-Type", "application/jose+json"}},
                .body = signed_jws(credential, directory.new_order, nonce, identifiers_json(identifiers), true),
                .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
            });

            std::cout << "\n========== RAW ORDER RESPONSE ==========\n";
            std::cout << order_response.body << "\n";
            std::cout << "========================================\n";

            auto authz_urls =
                find_url_array(order_response.body, "authorizations");

            std::cout << "parsed authz count="
                      << authz_urls.size()
                      << "\n";

            if (order_response.status_code < 200 || order_response.status_code >= 300)
            {
                return {.error = "upstream ACME newOrder failed: " + order_response.body};
            }

            domain::AcmeRelayOrderResult result{
                .success = true,
                .status = util::json::find_string(order_response.body, "status").value_or("pending"),
                .upstream_order_url = header_value(order_response, "location"),
                .upstream_finalize_url = util::json::find_string(order_response.body, "finalize").value_or(""),
                .upstream_certificate_url = util::json::find_string(order_response.body, "certificate").value_or(""),
                .raw_response = order_response.body,
            };

            auto next_nonce = header_value(order_response, "replay-nonce");
            const auto account_jwk = jwk_from_private_key(credential.account_key_pem);
            for (const auto &authz_url : find_url_array(order_response.body, "authorizations"))
            {
                if (next_nonce.empty())
                {
                    auto fresh_nonce = http_.execute({.method = "HEAD", .url = directory.new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
                    next_nonce = header_value(fresh_nonce, "replay-nonce");
                }
                const auto authz_response = http_.execute({
                    .method = "POST",
                    .url = authz_url,
                    .headers = {{"Content-Type", "application/jose+json"}},
                    .body = signed_jws(credential, authz_url, next_nonce, "", true),
                    .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
                });
                next_nonce = header_value(authz_response, "replay-nonce");
                if (authz_response.status_code < 200 || authz_response.status_code >= 300)
                {
                    return {.error = "upstream ACME authorization fetch failed: " + authz_response.body};
                }
                auto identifier = util::json::find_object(authz_response.body, "identifier").value_or("{}");
                result.authorizations.push_back({
                    .status = util::json::find_string(authz_response.body, "status").value_or("pending"),
                    .identifier_type = util::json::find_string(identifier, "type").value_or("dns"),
                    .identifier_value = util::json::find_string(identifier, "value").value_or(""),
                    .expires_at = util::json::find_string(authz_response.body, "expires").value_or(""),
                    .challenges = parse_http01_challenges(authz_response.body, account_jwk),
                    .upstream_url = authz_url,
                });
            }
            return result;
        }
        catch (const std::exception &ex)
        {
            return {.error = ex.what()};
        }
    }

    domain::CertificateIssueResult UpstreamAcmeCertificateAuthority::acknowledge_challenge(
        const std::string &challenge_url,
        const domain::EabMapping &mapping) const
    {
        try
        {
            auto credential = credential_for(mapping);
            auto nonce_response = http_.execute({.method = "HEAD", .url = credential.directory_url, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            auto directory_response = http_.execute({.method = "GET", .url = credential.directory_url, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            const auto new_nonce = util::json::find_string(directory_response.body, "newNonce").value_or("");
            nonce_response = http_.execute({.method = "HEAD", .url = new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            const auto nonce = header_value(nonce_response, "replay-nonce");
            const auto response = http_.execute({
                .method = "POST",
                .url = challenge_url,
                .headers = {{"Content-Type", "application/jose+json"}},
                .body = signed_jws(credential, challenge_url, nonce, "{}", true),
                .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
            });

            std::cout << "\n=== UPSTREAM CHALLENGE ACK RESPONSE ===\n";
            std::cout << response.body << "\n";
            std::cout << "=======================================\n";

            return {
                .success = response.status_code >= 200 && response.status_code < 300,
                .raw_response = response.body,
                .error = response.status_code >= 200 && response.status_code < 300 ? "" : response.body,
            };
        }
        catch (const std::exception &ex)
        {
            return {.error = ex.what()};
        }
    }

    domain::CertificateIssueResult UpstreamAcmeCertificateAuthority::issue_certificate(
        const domain::CertificateOrderRequest &request,
        const domain::EabMapping &mapping) const
    {
        try
        {
            auto credential = credential_for(mapping);
            if (request.username.empty())
            {
                return {.error = "missing local order id for upstream ACME finalization"};
            }

            const auto order_url = request.username;
            const auto finalize_url = request.enrollment_code;
            if (finalize_url.empty())
            {
                return {.error = "missing upstream ACME finalize URL"};
            }

            auto directory_response = http_.execute({.method = "GET", .url = credential.directory_url, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            const auto new_nonce = util::json::find_string(directory_response.body, "newNonce").value_or("");
            auto nonce_response = http_.execute({.method = "HEAD", .url = new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
            auto nonce = header_value(nonce_response, "replay-nonce");

            const auto finalize_response = http_.execute({
                .method = "POST",
                .url = finalize_url,
                .headers = {{"Content-Type", "application/jose+json"}},
                .body = signed_jws(credential, finalize_url, nonce, "{\"csr\":\"" + csr_der_b64url(request.csr_pem) + "\"}", true),
                .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
            });
            if (finalize_response.status_code < 200 || finalize_response.status_code >= 300)
            {
                return {.raw_response = finalize_response.body, .error = "upstream ACME finalize failed: " + finalize_response.body};
            }

            nonce = header_value(finalize_response, "replay-nonce");
            std::string certificate_url = util::json::find_string(finalize_response.body, "certificate").value_or("");
            for (int attempt = 0; certificate_url.empty() && attempt < 12; ++attempt)
            {
                if (nonce.empty())
                {
                    nonce_response = http_.execute({.method = "HEAD", .url = new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
                    nonce = header_value(nonce_response, "replay-nonce");
                }
                const auto order_response = http_.execute({
                    .method = "POST",
                    .url = order_url,
                    .headers = {{"Content-Type", "application/jose+json"}},
                    .body = signed_jws(credential, order_url, nonce, "", true),
                    .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
                });
                nonce = header_value(order_response, "replay-nonce");
                certificate_url = util::json::find_string(order_response.body, "certificate").value_or("");
                if (util::json::find_string(order_response.body, "status") == std::optional<std::string>{"invalid"})
                {
                    return {.raw_response = order_response.body, .error = "upstream ACME order became invalid"};
                }
            }
            if (certificate_url.empty())
            {
                return {.error = "upstream ACME order did not produce a certificate URL"};
            }

            if (nonce.empty())
            {
                nonce_response = http_.execute({.method = "HEAD", .url = new_nonce, .insecure_skip_tls_verify = credential.insecure_skip_tls_verify});
                nonce = header_value(nonce_response, "replay-nonce");
            }
            const auto cert_response = http_.execute({
                .method = "POST",
                .url = certificate_url,
                .headers = {{"Content-Type", "application/jose+json"}},
                .body = signed_jws(credential, certificate_url, nonce, "", true),
                .insecure_skip_tls_verify = credential.insecure_skip_tls_verify,
            });
            return {
                .success = cert_response.status_code >= 200 && cert_response.status_code < 300,
                .certificate_pem_or_der = cert_response.body,
                .raw_response = cert_response.body,
                .error = cert_response.status_code >= 200 && cert_response.status_code < 300 ? "" : cert_response.body,
            };
        }
        catch (const std::exception &ex)
        {
            return {.error = ex.what()};
        }
    }

} // namespace acme::infrastructure
