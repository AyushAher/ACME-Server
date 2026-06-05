#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileAcmeOrderRepository final : public application::AcmeOrderRepository {
  public:
    explicit FileAcmeOrderRepository(std::string data_dir);
    domain::AcmeOrder save(const domain::AcmeOrder& order) override;
    domain::AcmeOrder update(const domain::AcmeOrder& order) override;
    std::optional<domain::AcmeOrder> find_by_id(const std::string& order_id) const override;
    std::vector<domain::AcmeOrder> find_by_account_id(const std::string& account_id) const override;

  private:
    std::string data_dir_;
    std::string path_for(const std::string& order_id) const;
    static std::vector<std::string> encode_identifiers(const std::vector<domain::Identifier>& identifiers);
    static std::vector<domain::Identifier> decode_identifiers(const std::vector<std::string>& lines);
};

}  // namespace acme::infrastructure
