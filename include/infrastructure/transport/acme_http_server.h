#pragma once

#include <string>

#include "application/acme_account_service.h"
#include "application/acme_workflow_service.h"
#include "application/nonce_service.h"

namespace acme::infrastructure::transport {

struct ServerOptions {
    std::string host;
    int port {8080};
    std::string base_url;
};

class AcmeHttpServer {
  public:
    AcmeHttpServer(
        ServerOptions options,
        application::NonceService& nonce_service,
        const application::AcmeAccountService& account_service,
        const application::AcmeWorkflowService& workflow_service);

    void run() const;

  private:
    ServerOptions options_;
    application::NonceService& nonce_service_;
    const application::AcmeAccountService& account_service_;
    const application::AcmeWorkflowService& workflow_service_;

    std::string handle_request(const std::string& request) const;
};

}  // namespace acme::infrastructure::transport
