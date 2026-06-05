#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileAcmeCertificateRepository final : public application::AcmeCertificateRepository {
  public:
    explicit FileAcmeCertificateRepository(std::string data_dir);
    domain::AcmeCertificate save(const domain::AcmeCertificate& certificate) override;
    std::optional<domain::AcmeCertificate> find_by_id(const std::string& certificate_id) const override;

  private:
    std::string data_dir_;
    std::string path_for(const std::string& certificate_id) const;
};

}  // namespace acme::infrastructure
