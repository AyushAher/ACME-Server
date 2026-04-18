#pragma once

#include <string>

#include "infrastructure/ejbca_certificate_authority.h"

namespace acme::infrastructure::config {

struct AppConfig {
    std::string host {"0.0.0.0"};
    int port {18080};
    std::string base_url {"http://127.0.0.1:18080"};
    std::string data_dir {"./data"};
    std::string storage_backend {"file"};
    std::string eab_mappings_file {"./data/eab_mappings.csv"};
    std::string accounts_file {"./data/acme_accounts.tsv"};
    std::string nonces_file {"./data/nonces.txt"};
    std::string postgres_connection_string {"host=127.0.0.1 port=5432 dbname=acme user=acme password=acme"};
    std::string ca_backend {"openssl"};
    std::string openssl_ca_name {"OpenSSL-Aerovia"};
    std::string openssl_intermediate_dir {"/Users/ayushaher/Documents/Certificates/pki/aerovia/intermediate"};
    std::string openssl_chain_file {
        "/Users/ayushaher/Documents/Certificates/pki/aerovia/intermediate/certs/ca-chain.crt"};
    int openssl_valid_days {90};
    EjbcaClientConfig ejbca;
};

AppConfig load_from_file(const std::string& path);

}  // namespace acme::infrastructure::config
