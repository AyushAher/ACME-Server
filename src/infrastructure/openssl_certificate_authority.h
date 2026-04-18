#pragma once

#include "application/interfaces.h"

namespace acme::infrastructure {

struct OpenSslCertificateAuthorityConfig {
    std::string ca_name;
    std::string intermediate_dir;
    std::string chain_file;
    std::string working_dir;
    int valid_days {90};
};

class OpenSslCertificateAuthority final : public application::CertificateAuthority {
  public:
    explicit OpenSslCertificateAuthority(OpenSslCertificateAuthorityConfig config);

    std::string authority_name() const override;
    domain::CertificateIssueResult issue_certificate(
        const domain::CertificateOrderRequest& request,
        const domain::EabMapping& mapping) const override;

  private:
    OpenSslCertificateAuthorityConfig config_;

    static std::string shell_escape(const std::string& value);
};

}  // namespace acme::infrastructure
