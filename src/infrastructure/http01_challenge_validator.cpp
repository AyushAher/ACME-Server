#include "infrastructure/http01_challenge_validator.h"

#include "infrastructure/util/command_runner.h"

namespace acme::infrastructure {

domain::CertificateIssueResult Http01ChallengeValidator::validate_http_01(
    const std::string& identifier,
    const std::string& token,
    const std::string& expected_key_authorization) const {
    const auto command =
        "curl -fsSL --max-time 10 http://" + identifier + "/.well-known/acme-challenge/" + token;
    const auto result = util::run_command(command);
    if (result.exit_code != 0) {
        return {.error = "http-01 fetch failed: " + result.output};
    }

    std::string body = result.output;
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' ' || body.back() == '\t')) {
        body.pop_back();
    }
    if (body != expected_key_authorization) {
        return {.error = "http-01 content mismatch"};
    }

    return {.success = true};
}

}  // namespace acme::infrastructure
