#include "infrastructure/config/app_config.h"

#include <fstream>
#include <stdexcept>

namespace acme::infrastructure::config {

namespace {

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

bool as_bool(const std::string& value) {
    return value == "true" || value == "1" || value == "yes";
}

}  // namespace

AppConfig load_from_file(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("unable to open config file: " + path);
    }

    AppConfig config;
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line.starts_with('#')) {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = trim(line.substr(0, separator));
        const auto value = trim(line.substr(separator + 1));

        if (key == "host") {
            config.host = value;
        } else if (key == "port") {
            config.port = std::stoi(value);
        } else if (key == "base_url") {
            config.base_url = value;
        } else if (key == "data_dir") {
            config.data_dir = value;
        } else if (key == "storage_backend") {
            config.storage_backend = value;
        } else if (key == "eab_mappings_file") {
            config.eab_mappings_file = value;
        } else if (key == "accounts_file") {
            config.accounts_file = value;
        } else if (key == "nonces_file") {
            config.nonces_file = value;
        } else if (key == "postgres_connection_string") {
            config.postgres_connection_string = value;
        } else if (key == "ca_backend") {
            config.ca_backend = value;
        } else if (key == "openssl_ca_name") {
            config.openssl_ca_name = value;
        } else if (key == "openssl_intermediate_dir") {
            config.openssl_intermediate_dir = value;
        } else if (key == "openssl_chain_file") {
            config.openssl_chain_file = value;
        } else if (key == "openssl_valid_days") {
            config.openssl_valid_days = std::stoi(value);
        } else if (key == "ejbca_base_url") {
            config.ejbca.base_url = value;
        } else if (key == "ejbca_ca_name") {
            config.ejbca.ca_name = value;
        } else if (key == "ejbca_client_pkcs12_path") {
            config.ejbca.client_pkcs12_path = value;
        } else if (key == "ejbca_client_pkcs12_password") {
            config.ejbca.client_pkcs12_password = value;
        } else if (key == "ejbca_insecure_skip_tls_verify") {
            config.ejbca.insecure_skip_tls_verify = as_bool(value);
        }
    }

    return config;
}

}  // namespace acme::infrastructure::config
