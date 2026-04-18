#pragma once

#include <string>

#include "application/interfaces.h"

namespace acme::infrastructure {

class FileAcmeAuthorizationRepository final : public application::AcmeAuthorizationRepository {
  public:
    explicit FileAcmeAuthorizationRepository(std::string data_dir);
    domain::AcmeAuthorization save(const domain::AcmeAuthorization& authorization) override;
    domain::AcmeAuthorization update(const domain::AcmeAuthorization& authorization) override;
    std::optional<domain::AcmeAuthorization> find_by_id(const std::string& authorization_id) const override;
    std::optional<domain::AcmeAuthorization> find_by_challenge_id(const std::string& challenge_id) const override;

  private:
    std::string data_dir_;
    std::string path_for(const std::string& authorization_id) const;
    static std::vector<std::string> encode_challenges(const std::vector<domain::AcmeChallenge>& challenges);
    static std::vector<domain::AcmeChallenge> decode_challenges(const std::vector<std::string>& lines);
};

}  // namespace acme::infrastructure
