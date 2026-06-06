#include "discovery/certificate_discovery_service.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <array>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace discovery
{

    namespace
    {

        struct SocketCloser
        {
            void operator()(int *fd) const
            {
                if (fd != nullptr && *fd >= 0)
                {
                    close(*fd);
                }
                delete fd;
            }
        };

        struct AddrInfoDeleter
        {
            void operator()(addrinfo *info) const
            {
                if (info != nullptr)
                {
                    freeaddrinfo(info);
                }
            }
        };

        struct SslCtxDeleter
        {
            void operator()(SSL_CTX *ctx) const
            {
                if (ctx != nullptr)
                {
                    SSL_CTX_free(ctx);
                }
            }
        };

        struct SslDeleter
        {
            void operator()(SSL *ssl) const
            {
                if (ssl != nullptr)
                {
                    SSL_free(ssl);
                }
            }
        };

        struct X509Deleter
        {
            void operator()(X509 *cert) const
            {
                if (cert != nullptr)
                {
                    X509_free(cert);
                }
            }
        };

        struct GeneralNamesDeleter
        {
            void operator()(GENERAL_NAMES *names) const
            {
                if (names != nullptr)
                {
                    GENERAL_NAMES_free(names);
                }
            }
        };

        std::string openssl_error_string()
        {
            const auto error_code = ERR_get_error();
            if (error_code == 0)
            {
                return "unknown OpenSSL error";
            }

            std::array<char, 256> buffer{};
            ERR_error_string_n(error_code, buffer.data(), buffer.size());
            return std::string(buffer.data());
        }

        std::string bio_to_string(BIO *bio)
        {
            BUF_MEM *buffer = nullptr;
            BIO_get_mem_ptr(bio, &buffer);
            if (buffer == nullptr || buffer->data == nullptr)
            {
                return {};
            }
            return std::string(buffer->data, buffer->length);
        }

        std::string x509_name_to_string(X509_NAME *name)
        {
            std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
            if (!bio)
            {
                return {};
            }
            X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253);
            return bio_to_string(bio.get());
        }

        std::string asn1_time_to_string(const ASN1_TIME *time)
        {
            std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
            if (!bio)
            {
                return {};
            }
            ASN1_TIME_print(bio.get(), time);
            return bio_to_string(bio.get());
        }

        std::string serial_to_hex(ASN1_INTEGER *serial)
        {
            std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(serial, nullptr), BN_free);
            if (!bn)
            {
                return {};
            }

            char *hex = BN_bn2hex(bn.get());
            if (hex == nullptr)
            {
                return {};
            }
            std::string output(hex);
            OPENSSL_free(hex);
            return output;
        }

        std::string fingerprint_sha256(X509 *certificate)
        {
            unsigned int length = 0;
            unsigned char digest[EVP_MAX_MD_SIZE]{};
            if (X509_digest(certificate, EVP_sha256(), digest, &length) != 1)
            {
                return {};
            }

            std::ostringstream output;
            for (unsigned int index = 0; index < length; ++index)
            {
                if (index > 0)
                {
                    output << ":";
                }
                output << std::uppercase << std::hex;
                output.width(2);
                output.fill('0');
                output << static_cast<int>(digest[index]);
            }
            return output.str();
        }

        bool is_ipv4_literal(const std::string &host)
        {
            in_addr address{};
            return inet_pton(AF_INET, host.c_str(), &address) == 1;
        }

        std::optional<std::uint32_t> ipv4_to_uint(const std::string &ip)
        {
            in_addr address{};
            if (inet_pton(AF_INET, ip.c_str(), &address) != 1)
            {
                return std::nullopt;
            }
            return ntohl(address.s_addr);
        }

        std::string uint_to_ipv4(std::uint32_t value)
        {
            in_addr address{};
            address.s_addr = htonl(value);
            std::array<char, INET_ADDRSTRLEN> buffer{};
            const auto *text = inet_ntop(AF_INET, &address, buffer.data(), buffer.size());
            return text == nullptr ? std::string{} : std::string(text);
        }

        int connect_with_timeout(const addrinfo &entry, int timeout_ms)
        {
            int socket_fd = socket(entry.ai_family, entry.ai_socktype, entry.ai_protocol);
            if (socket_fd < 0)
            {
                return -1;
            }

            const int flags = fcntl(socket_fd, F_GETFL, 0);
            if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0)
            {
                close(socket_fd);
                return -1;
            }

            const int result = connect(socket_fd, entry.ai_addr, entry.ai_addrlen);
            if (result == 0)
            {
                fcntl(socket_fd, F_SETFL, flags);
                return socket_fd;
            }

            if (errno != EINPROGRESS)
            {
                close(socket_fd);
                return -1;
            }

            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(socket_fd, &write_set);

            timeval timeout{};
            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;

            const int selected = select(socket_fd + 1, nullptr, &write_set, nullptr, &timeout);
            if (selected <= 0)
            {
                close(socket_fd);
                return -1;
            }

            int socket_error = 0;
            socklen_t socket_error_size = sizeof(socket_error);
            if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) < 0 || socket_error != 0)
            {
                close(socket_fd);
                return -1;
            }

            fcntl(socket_fd, F_SETFL, flags);

            timeval io_timeout{};
            io_timeout.tv_sec = timeout_ms / 1000;
            io_timeout.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
            return socket_fd;
        }

        std::vector<std::string> expand_range(const std::string &start_ip, const std::string &end_ip, int max_hosts)
        {
            const auto start = ipv4_to_uint(start_ip);
            const auto end = ipv4_to_uint(end_ip);
            if (!start.has_value() || !end.has_value())
            {
                throw std::runtime_error("range requires valid IPv4 addresses");
            }
            if (*start > *end)
            {
                throw std::runtime_error("range start must be less than or equal to range end");
            }

            std::vector<std::string> hosts;
            for (std::uint32_t current = *start; current <= *end; ++current)
            {
                if (static_cast<int>(hosts.size()) >= max_hosts)
                {
                    break;
                }
                hosts.push_back(uint_to_ipv4(current));
                if (current == std::numeric_limits<std::uint32_t>::max())
                {
                    break;
                }
            }
            return hosts;
        }

        std::vector<std::string> expand_subnet_hosts(const std::string &cidr, int max_hosts)
        {
            const auto slash = cidr.find('/');
            if (slash == std::string::npos)
            {
                throw std::runtime_error("cidr must include prefix length");
            }

            const auto base_ip = cidr.substr(0, slash);
            const auto prefix = std::stoi(cidr.substr(slash + 1));
            if (prefix < 0 || prefix > 32)
            {
                throw std::runtime_error("cidr prefix must be between 0 and 32");
            }

            const auto address = ipv4_to_uint(base_ip);
            if (!address.has_value())
            {
                throw std::runtime_error("cidr requires a valid IPv4 base address");
            }

            const std::uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
            const std::uint32_t network = *address & mask;
            const std::uint32_t size = prefix == 32 ? 1u : (1u << (32 - prefix));

            std::uint32_t first = network;
            std::uint32_t last = network + size - 1;
            if (prefix <= 30)
            {
                first = network + 1;
                last = network + size - 2;
            }

            std::vector<std::string> hosts;
            for (std::uint32_t current = first; current <= last; ++current)
            {
                if (static_cast<int>(hosts.size()) >= max_hosts)
                {
                    break;
                }
                hosts.push_back(uint_to_ipv4(current));
                if (current == std::numeric_limits<std::uint32_t>::max())
                {
                    break;
                }
            }
            return hosts;
        }

    } // namespace

    CertificateDiscoveryResult CertificateDiscoveryService::discover_host(
        const std::string &host,
        int port,
        int timeout_ms) const
    {
        CertificateDiscoveryResult result;
        result.host = host;
        result.port = port;

        if (host.empty())
        {
            result.error = "host is required";
            return result;
        }
        if (port <= 0 || port > 65535)
        {
            result.error = "port must be between 1 and 65535";
            return result;
        }

        SSL_library_init();
        SSL_load_error_strings();

        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;

        addrinfo *raw_addresses = nullptr;
        const auto port_text = std::to_string(port);
        const int lookup_result = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &raw_addresses);
        if (lookup_result != 0)
        {
            result.error = gai_strerror(lookup_result);
            return result;
        }

        std::unique_ptr<addrinfo, AddrInfoDeleter> addresses(raw_addresses);
        int connected_fd = -1;
        for (auto *entry = addresses.get(); entry != nullptr; entry = entry->ai_next)
        {
            connected_fd = connect_with_timeout(*entry, timeout_ms);
            if (connected_fd >= 0)
            {
                break;
            }
        }

        if (connected_fd < 0)
        {
            result.error = "failed to connect";
            return result;
        }

        std::unique_ptr<int, SocketCloser> socket_holder(new int(connected_fd));
        result.tcp_connected = true;

        std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx(SSL_CTX_new(TLS_client_method()));
        if (!ctx)
        {
            result.error = openssl_error_string();
            return result;
        }
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

        std::unique_ptr<SSL, SslDeleter> ssl(SSL_new(ctx.get()));
        if (!ssl)
        {
            result.error = openssl_error_string();
            return result;
        }

        SSL_set_fd(ssl.get(), *socket_holder);
        if (!is_ipv4_literal(host))
        {
            SSL_set_tlsext_host_name(ssl.get(), host.c_str());
        }

        if (SSL_connect(ssl.get()) != 1)
        {
            result.error = openssl_error_string();
            return result;
        }

        result.tls_established = true;
        std::unique_ptr<X509, X509Deleter> certificate(SSL_get1_peer_certificate(ssl.get()));
        if (!certificate)
        {
            result.error = "peer did not present a certificate";
            return result;
        }

        result.subject = x509_name_to_string(X509_get_subject_name(certificate.get()));
        result.issuer = x509_name_to_string(X509_get_issuer_name(certificate.get()));
        result.serial_hex = serial_to_hex(X509_get_serialNumber(certificate.get()));
        result.not_before = asn1_time_to_string(X509_get0_notBefore(certificate.get()));
        result.not_after = asn1_time_to_string(X509_get0_notAfter(certificate.get()));
        result.sha256_fingerprint = fingerprint_sha256(certificate.get());

        std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter> names(
            static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(certificate.get(), NID_subject_alt_name, nullptr, nullptr)));
        if (names)
        {
            const int count = sk_GENERAL_NAME_num(names.get());
            for (int index = 0; index < count; ++index)
            {
                const auto *general_name = sk_GENERAL_NAME_value(names.get(), index);
                if (general_name->type == GEN_DNS)
                {
                    const auto *dns = ASN1_STRING_get0_data(general_name->d.dNSName);
                    if (dns != nullptr)
                    {
                        result.dns_names.emplace_back(reinterpret_cast<const char *>(dns));
                    }
                }
                else if (general_name->type == GEN_IPADD)
                {
                    const auto *ip_data = ASN1_STRING_get0_data(general_name->d.iPAddress);
                    const auto ip_length = ASN1_STRING_length(general_name->d.iPAddress);
                    if (ip_data != nullptr && ip_length == 4)
                    {
                        std::array<char, INET_ADDRSTRLEN> buffer{};
                        if (inet_ntop(AF_INET, ip_data, buffer.data(), buffer.size()) != nullptr)
                        {
                            result.ip_addresses.emplace_back(buffer.data());
                        }
                    }
                }
            }
        }

        return result;
    }

    std::vector<CertificateDiscoveryResult> CertificateDiscoveryService::discover_range(
        const std::string &start_ip,
        const std::string &end_ip,
        int port,
        int timeout_ms,
        int max_hosts) const
    {
        std::vector<CertificateDiscoveryResult> results;
        for (const auto &host : expand_range(start_ip, end_ip, max_hosts))
        {
            results.push_back(discover_host(host, port, timeout_ms));
        }
        return results;
    }

    std::vector<CertificateDiscoveryResult> CertificateDiscoveryService::discover_subnet(
        const std::string &cidr,
        int port,
        int timeout_ms,
        int max_hosts) const
    {
        std::vector<CertificateDiscoveryResult> results;
        for (const auto &host : expand_subnet_hosts(cidr, max_hosts))
        {
            results.push_back(discover_host(host, port, timeout_ms));
        }
        return results;
    }

} // namespace discovery
