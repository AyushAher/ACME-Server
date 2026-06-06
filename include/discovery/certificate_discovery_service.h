#pragma once

#include <string>
#include <vector>

namespace discovery
{

    struct CertificateDiscoveryResult
    {
        std::string host;
        int port{443};
        bool tcp_connected{false};
        bool tls_established{false};
        std::string subject;
        std::string issuer;
        std::string serial_hex;
        std::string not_before;
        std::string not_after;
        std::string sha256_fingerprint;
        std::vector<std::string> dns_names;
        std::vector<std::string> ip_addresses;
        std::string error;
    };

    class CertificateDiscoveryService
    {
    public:
        CertificateDiscoveryResult discover_host(
            const std::string &host,
            int port = 443,
            int timeout_ms = 3000) const;

        std::vector<CertificateDiscoveryResult> discover_range(
            const std::string &start_ip,
            const std::string &end_ip,
            int port = 443,
            int timeout_ms = 3000,
            int max_hosts = 256) const;

        std::vector<CertificateDiscoveryResult> discover_subnet(
            const std::string &cidr,
            int port = 443,
            int timeout_ms = 3000,
            int max_hosts = 256) const;
    };

} // namespace discovery
