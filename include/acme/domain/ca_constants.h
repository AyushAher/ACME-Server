#pragma once

#include <string>
#include <string_view>

#include "acme/domain/acme_types.h"

namespace acme::domain
{

    namespace ca_names
    {
        inline constexpr const char *LETSENCRYPT_PREFIX = "LetsEncrypt";
        inline constexpr const char *ZEROSSL_PREFIX = "ZeroSSL";

        inline constexpr const char *LETSENCRYPT_PRODUCTION = "LetsEncrypt-Production";
        inline constexpr const char *LETSENCRYPT_STAGING = "LetsEncrypt-Staging";
        inline constexpr const char *ZEROSSL_PRODUCTION = "ZeroSSL-Production";
    } // namespace ca_names

    namespace ca_directory_hosts
    {
        inline constexpr const char *LETSENCRYPT = "letsencrypt.org";
        inline constexpr const char *ZEROSSL = "zerossl.com";
    } // namespace ca_directory_hosts

    namespace ca_directory_urls
    {
        inline constexpr const char *LETSENCRYPT_PRODUCTION =
            "https://acme-v02.api.letsencrypt.org/directory";
        inline constexpr const char *LETSENCRYPT_STAGING =
            "https://acme-staging-v02.api.letsencrypt.org/directory";
        inline constexpr const char *ZEROSSL_PRODUCTION =
            "https://acme.zerossl.com/v2/DV90/directory";
    } // namespace ca_directory_urls

    namespace acme_directory_meta
    {
        inline constexpr const char *HTTP01_PROXY_FOR = "LetsEncrypt,ZeroSSL";
    } // namespace acme_directory_meta

    inline bool ca_name_has_prefix(std::string_view ca_name, std::string_view prefix)
    {
        return ca_name.size() >= prefix.size() &&
               ca_name.compare(0, prefix.size(), prefix) == 0;
    }

    inline bool is_letsencrypt_credential(const CaCredential &credential)
    {
        return ca_name_has_prefix(credential.ca_name, ca_names::LETSENCRYPT_PREFIX) ||
               credential.directory_url.find(ca_directory_hosts::LETSENCRYPT) != std::string::npos;
    }

    inline bool is_zerossl_credential(const CaCredential &credential)
    {
        return ca_name_has_prefix(credential.ca_name, ca_names::ZEROSSL_PREFIX) ||
               credential.directory_url.find(ca_directory_hosts::ZEROSSL) != std::string::npos;
    }

    inline bool credential_supports_http01_proxy(const CaCredential &credential)
    {
        return is_letsencrypt_credential(credential) || is_zerossl_credential(credential);
    }

} // namespace acme::domain
