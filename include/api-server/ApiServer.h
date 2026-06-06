#pragma once

#include <string>

#include "acme/application/acme_account_service.h"
#include "acme/application/acme_workflow_service.h"
#include "acme/application/nonce_service.h"
#include "acme/infrastructure/transport/acme_http_server.h"

namespace api_server
{

  class ApiServer
  {
  public:
    ApiServer(
        common::ServerOptions options,
        acme::infrastructure::transport::AcmeHttpServer &http_server);

    void run() const;
    std::string handle_request(const std::string &request) const;

  private:
    common::ServerOptions options_;
    acme::infrastructure::transport::AcmeHttpServer &http_server_;
  };

} // namespace api_server
