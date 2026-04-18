#include "infrastructure/ejbca_certificate_authority.h"

#include <sstream>

namespace acme::infrastructure {

EjbcaCertificateAuthority::EjbcaCertificateAuthority(EjbcaClientConfig config, ShellHttpClient http_client)
    : config_(std::move(config)), http_client_(std::move(http_client)) {}

std::string EjbcaCertificateAuthority::authority_name() const {
    return config_.ca_name;
}

domain::CertificateIssueResult EjbcaCertificateAuthority::issue_certificate(
    const domain::CertificateOrderRequest& request,
    const domain::EabMapping& mapping) const {
    std::ostringstream body;
    body << "{"
         << "\"certificate_request\":\"" << escape_json(request.csr_pem) << "\","
         << "\"certificate_profile_name\":\"" << escape_json(request.certificate_profile_name) << "\","
         << "\"end_entity_profile_name\":\"" << escape_json(request.end_entity_profile_name) << "\","
         << "\"certificate_authority_name\":\"" << escape_json(config_.ca_name) << "\","
         << "\"username\":\"" << escape_json(request.username) << "\","
         << "\"password\":\"" << escape_json(request.enrollment_code) << "\","
         << "\"include_chain\":" << (request.include_chain ? "true" : "false") << ","
         << "\"account_binding_id\":\"" << escape_json(mapping.client_id) << "\"";

    if (request.email.has_value()) {
        body << ",\"email\":\"" << escape_json(*request.email) << "\"";
    }

    body << "}";

    const HttpRequest http_request {
        .method = "POST",
        .url = config_.base_url + "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll",
        .headers = {
            {"accept", "application/json"},
            {"content-type", "application/json"},
        },
        .body = body.str(),
        .client_pkcs12_bundle = config_.client_pkcs12_path,
        .client_pkcs12_password = config_.client_pkcs12_password,
        .insecure_skip_tls_verify = config_.insecure_skip_tls_verify,
    };

    const auto response = http_client_.execute(http_request);
    if (!response.error.empty()) {
        return {.error = response.error};
    }
    if (response.status_code < 200 || response.status_code >= 300) {
        return {.raw_response = response.body, .error = "EJBCA enrollment request failed"};
    }

    return {
        .success = true,
        .certificate_pem_or_der = response.body,
        .raw_response = response.body,
    };
}

std::string EjbcaCertificateAuthority::escape_json(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (const auto ch : value) {
        switch (ch) {
            case '\\':
                output += "\\\\";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                output.push_back(ch);
                break;
        }
    }
    return output;
}

}  // namespace acme::infrastructure
