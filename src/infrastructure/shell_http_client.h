#pragma once

#include <map>
#include <string>

namespace acme::infrastructure
{

  struct HttpRequest
  {
    std::string method;
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
    std::optional<std::string> client_pkcs12_bundle;
    std::optional<std::string> client_pkcs12_password;
    bool insecure_skip_tls_verify{false};
  };

  struct HttpResponse
  {
    int status_code{0};
    std::string body;
    std::string error;
  };

  class ShellHttpClient
  {
  public:
    HttpResponse execute(const HttpRequest &request) const;

  private:
    static std::string shell_escape(const std::string &value);
  };

} // namespace acme::infrastructure
