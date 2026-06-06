#pragma once

#include <string>

#include "acme/application/acme_account_service.h"
#include "acme/application/acme_workflow_service.h"
#include "acme/application/nonce_service.h"

namespace acme::infrastructure::transport
{

  class AcmeHttpServer
  {
  public:
    AcmeHttpServer(
        ServerOptions options,
        application::NonceService &nonce_service,
        const application::AcmeAccountService &account_service,
        const application::AcmeWorkflowService &workflow_service);

    // void run() const;
    std::string handle_request(const std::string &request) const;

  private:
    application::NonceService &nonce_service_;
    const application::AcmeAccountService &account_service_;
    const application::AcmeWorkflowService &workflow_service_;
    ServerOptions options;
  };

} // namespace acme::infrastructure::transport
