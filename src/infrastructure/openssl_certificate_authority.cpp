#include "infrastructure/openssl_certificate_authority.h"

#include <cctype>
#include <filesystem>

#include "infrastructure/util/command_runner.h"
#include "infrastructure/util/file_store.h"
#include "infrastructure/util/random.h"

namespace acme::infrastructure {

namespace {

std::string san_value(std::string value) {
    if (const auto colon = value.find(':'); colon != std::string::npos) {
        if (value.find(':', colon + 1) == std::string::npos) {
            value = value.substr(0, colon);
        }
    }
    return value;
}

std::string default_common_name(const std::vector<domain::Identifier>& identifiers) {
    for (const auto& identifier : identifiers) {
        if (identifier.type == "dns" || identifier.type == "ip") {
            const auto value = san_value(identifier.value);
            if (!value.empty()) {
                return value;
            }
        }
    }
    return "acme-issued";
}

std::string subject_rdn_value(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const auto ch : value) {
        if (ch == '/' || ch == '\\') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.pop_back();
    }
    return value;
}

std::string normalize_serial(std::string value) {
    value = trim(std::move(value));
    if (value.empty()) {
        return "1000";
    }
    for (auto& ch : value) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string increment_hex_string(std::string value) {
    value = normalize_serial(std::move(value));
    int carry = 1;
    for (auto it = value.rbegin(); it != value.rend(); ++it) {
        int digit = 0;
        if (*it >= '0' && *it <= '9') {
            digit = *it - '0';
        } else if (*it >= 'A' && *it <= 'F') {
            digit = 10 + (*it - 'A');
        } else {
            continue;
        }

        digit += carry;
        carry = digit / 16;
        digit %= 16;
        *it = static_cast<char>(digit < 10 ? ('0' + digit) : ('A' + digit - 10));
        if (carry == 0) {
            break;
        }
    }

    if (carry != 0) {
        value.insert(value.begin(), '1');
    }
    return value;
}

std::string command_value(const util::CommandResult& result, const std::string& prefix) {
    for (const auto& line : util::split(result.output, '\n')) {
        if (line.rfind(prefix, 0) == 0) {
            return trim(line.substr(prefix.size()));
        }
    }
    return {};
}

}  // namespace

OpenSslCertificateAuthority::OpenSslCertificateAuthority(OpenSslCertificateAuthorityConfig config)
    : config_(std::move(config)) {}

std::string OpenSslCertificateAuthority::authority_name() const {
    return config_.ca_name;
}

domain::CertificateIssueResult OpenSslCertificateAuthority::issue_certificate(
    const domain::CertificateOrderRequest& request,
    const domain::EabMapping& mapping) const {
    if (mapping.ca != config_.ca_name) {
        return {.error = "OpenSSL CA backend does not match EAB mapping CA"};
    }

    const auto job_id = util::random_token(9);
    const auto base_work_dir = std::filesystem::absolute(config_.working_dir);
    const auto work_dir = (base_work_dir / "openssl" / job_id).string();
    std::filesystem::create_directories(work_dir);

    const auto csr_path = work_dir + "/request.csr";
    const auto cert_path = work_dir + "/certificate.pem";
    const auto ext_path = work_dir + "/extensions.cnf";
    const auto serial_path = config_.intermediate_dir + "/serial";
    const auto index_path = config_.intermediate_dir + "/index.txt";
    const auto newcerts_dir = config_.intermediate_dir + "/newcerts";
    const auto intermediate_cert = config_.intermediate_dir + "/certs/intermediate.crt";
    const auto intermediate_key = config_.intermediate_dir + "/private/intermediate.key";

    util::write_lines(csr_path, {request.csr_pem});

    util::write_lines(
        ext_path,
        {
            "[ acme_server_cert ]",
            "basicConstraints = critical, CA:false",
            "keyUsage = critical, digitalSignature, keyEncipherment",
            "extendedKeyUsage = serverAuth, clientAuth",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
            "subjectAltName = @alt_names",
            "[ alt_names ]",
        });

    std::vector<std::string> extension_lines = util::read_lines(ext_path);
    int dns_index = 1;
    int ip_index = 1;
    for (const auto& identifier : request.identifiers) {
        if (identifier.type == "dns") {
            extension_lines.push_back("DNS." + std::to_string(dns_index++) + " = " + san_value(identifier.value));
        } else if (identifier.type == "ip") {
            extension_lines.push_back("IP." + std::to_string(ip_index++) + " = " + san_value(identifier.value));
        }
    }
    util::write_lines(ext_path, extension_lines);

    const auto subject = "/CN=" + subject_rdn_value(default_common_name(request.identifiers));
    const auto serial_lines = util::read_lines(serial_path);
    const auto serial_hex = normalize_serial(serial_lines.empty() ? "1000" : serial_lines.front());

    const auto issue_command =
        "openssl x509 -req "
        "-CA " + shell_escape(intermediate_cert) + " "
        "-CAkey " + shell_escape(intermediate_key) + " "
        "-set_serial 0x" + serial_hex + " "
        "-sha256 "
        "-days " + std::to_string(config_.valid_days) + " "
        "-extfile " + shell_escape(ext_path) + " "
        "-extensions acme_server_cert "
        "-in " + shell_escape(csr_path) + " "
        "-out " + shell_escape(cert_path);

    const auto result = util::run_command(issue_command);
    if (result.exit_code != 0) {
        return {.raw_response = result.output, .error = "openssl x509 failed: " + result.output};
    }

    const auto cert_lines = util::read_lines(cert_path);
    if (cert_lines.empty()) {
        return {.error = "openssl did not produce a certificate"};
    }

    std::filesystem::create_directories(newcerts_dir);
    util::write_lines(newcerts_dir + "/" + serial_hex + ".pem", cert_lines);
    util::write_lines(serial_path, {increment_hex_string(serial_hex)});

    const auto inspect_result = util::run_command(
        "openssl x509 -in " + shell_escape(cert_path) + " -noout -enddate");
    const auto not_after = command_value(inspect_result, "notAfter=");
    if (!not_after.empty()) {
        util::append_line(
            index_path,
            "V\t" + not_after + "\t\t" + serial_hex + "\tunknown\t" + subject);
    }

    std::string leaf_pem;
    for (const auto& line : cert_lines) {
        leaf_pem += line + "\n";
    }

    std::string chain_pem = leaf_pem;
    for (const auto& line : util::read_lines(config_.chain_file)) {
        chain_pem += line + "\n";
    }

    return {
        .success = true,
        .certificate_pem_or_der = chain_pem,
        .raw_response = result.output,
    };
}

std::string OpenSslCertificateAuthority::shell_escape(const std::string& value) {
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
