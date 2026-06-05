#pragma once

#include <string>

#include "application/interfaces.h"
#include "infrastructure/shell_http_client.h"

namespace acme::infrastructure {

struct EjbcaClientConfig {
    std::string base_url;
    std::string ca_name;
    std::string client_pkcs12_path;
    std::string client_pkcs12_password;
    bool insecure_skip_tls_verify {false};
};

class EjbcaCertificateAuthority final : public application::CertificateAuthority {
  public:
    EjbcaCertificateAuthority(EjbcaClientConfig config, ShellHttpClient http_client);

    std::string authority_name() const override;
    domain::CertificateIssueResult issue_certificate(
        const domain::CertificateOrderRequest& request,
        const domain::EabMapping& mapping) const override;

  private:
    EjbcaClientConfig config_;
    ShellHttpClient http_client_;

    static std::string escape_json(const std::string& value);
};

}  // namespace acme::infrastructure
