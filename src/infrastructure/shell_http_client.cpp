#include "infrastructure/shell_http_client.h"

#include <array>
#include <cstdio>
#include <sstream>

namespace acme::infrastructure {

HttpResponse ShellHttpClient::execute(const HttpRequest& request) const {
    std::ostringstream command;
    command << "curl -s -X " << shell_escape(request.method) << " ";

    if (request.insecure_skip_tls_verify) {
        command << "-k ";
    }

    for (const auto& [header_name, header_value] : request.headers) {
        command << "-H " << shell_escape(header_name + ": " + header_value) << " ";
    }

    if (request.client_pkcs12_bundle.has_value()) {
        command << "--cert-type P12 --cert "
                << shell_escape(
                       *request.client_pkcs12_bundle + ":" + request.client_pkcs12_password.value_or(""))
                << " ";
    }

    if (!request.body.empty()) {
        command << "--data " << shell_escape(request.body) << " ";
    }

    command << "-w '\\n%{http_code}' " << shell_escape(request.url);

    std::array<char, 512> buffer {};
    std::string output;
    if (FILE* pipe = popen(command.str().c_str(), "r")) {
        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
            output += buffer.data();
        }
        pclose(pipe);
    } else {
        return {.error = "failed to launch curl"};
    }

    const auto separator = output.find_last_of('\n');
    if (separator == std::string::npos) {
        return {.error = "unable to parse HTTP response from curl"};
    }

    const auto body = output.substr(0, separator);
    const auto code_text = output.substr(separator + 1);

    try {
        return {.status_code = std::stoi(code_text), .body = body};
    } catch (...) {
        return {.body = body, .error = "invalid HTTP status code returned by curl"};
    }
}

std::string ShellHttpClient::shell_escape(const std::string& value) {
    std::string escaped = "'";
    for (const auto ch : value) {
        if (ch == '\'') {
            escaped += "'\\''";
        } else {
            escaped.push_back(ch);
        }
    }
    escaped += "'";
    return escaped;
}

}  // namespace acme::infrastructure
