#pragma once

#include <string>

#include "acme/application/eab_service.h"
#include "acme/application/interfaces.h"

namespace acme::application
{

  class AcmeAccountService
  {
  public:
    AcmeAccountService(AcmeAccountRepository &repository, const EabService &eab_service);
    domain::NewAccountResponse register_account(const domain::NewAccountRequest &request) const;

  private:
    AcmeAccountRepository &repository_;
    const EabService &eab_service_;
    static std::string next_account_id();
  };

} // namespace acme::application
