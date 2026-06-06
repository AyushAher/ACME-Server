#pragma once

#include <string>

#include "acme/application/acme_account_service.h"
#include "acme/application/acme_workflow_service.h"
#include "acme/application/nonce_service.h"
#include "acme/infrastructure/transport/acme_http_server.h"
#include "common/server_options.h"
#include "discovery/certificate_discovery_service.h"

namespace api_server
{

  class ApiServer
  {
  public:
    ApiServer(
        common::ServerOptions options,
        acme::infrastructure::transport::AcmeHttpServer &http_server,
        discovery::CertificateDiscoveryService &discovery_service);

    void run() const;
    std::string handle_request(const std::string &request) const;

  private:
    common::ServerOptions options_;
    acme::infrastructure::transport::AcmeHttpServer &http_server_;
    discovery::CertificateDiscoveryService &discovery_service_;
  };

} // namespace api_server
