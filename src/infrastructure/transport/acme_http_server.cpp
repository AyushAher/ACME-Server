#include "infrastructure/transport/acme_http_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>

#include "infrastructure/util/acme_protocol.h"
#include "infrastructure/util/base64url.h"
#include "infrastructure/util/json.h"

namespace acme::infrastructure::transport {

namespace {

struct ParsedRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

ParsedRequest parse_request(const std::string& raw) {
    ParsedRequest request;
    const auto header_end = raw.find("\r\n\r\n");
    const auto head = raw.substr(0, header_end);
    request.body = header_end == std::string::npos ? "" : raw.substr(header_end + 4);

    std::istringstream stream(head);
    std::string request_line;
    std::getline(stream, request_line);
    if (!request_line.empty() && request_line.back() == '\r') {
        request_line.pop_back();
    }

    std::istringstream request_line_stream(request_line);
    request_line_stream >> request.method >> request.path;

    std::string header_line;
    while (std::getline(stream, header_line)) {
        if (!header_line.empty() && header_line.back() == '\r') {
            header_line.pop_back();
        }
        const auto separator = header_line.find(':');
        if (separator == std::string::npos) {
            continue;
        }
        auto value = header_line.substr(separator + 1);
        if (!value.empty() && value.front() == ' ') {
            value.erase(0, 1);
        }
        request.headers[header_line.substr(0, separator)] = value;
    }

    return request;
}

std::string reason_phrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default: return "Unknown";
    }
}

std::string response(
    int status,
    const std::string& body,
    const std::map<std::string, std::string>& headers = {}) {
    std::ostringstream output;
    output << "HTTP/1.1 " << status << " " << reason_phrase(status) << "\r\n";
    for (const auto& [key, value] : headers) {
        output << key << ": " << value << "\r\n";
    }
    output << "Content-Length: " << body.size() << "\r\n";
    output << "Connection: close\r\n\r\n";
    output << body;
    return output.str();
}

std::optional<std::string> path_param(const std::string& path, const std::string& prefix, const std::string& suffix = "") {
    if (!path.starts_with(prefix)) {
        return std::nullopt;
    }
    auto value = path.substr(prefix.size());
    if (!suffix.empty()) {
        if (!value.ends_with(suffix)) {
            return std::nullopt;
        }
        value = value.substr(0, value.size() - suffix.size());
    }
    if (value.empty() || value.find('/') != std::string::npos) {
        return std::nullopt;
    }
    return value;
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::ostringstream output;
    output << "[";
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            output << ",";
        }
        output << "\"" << infrastructure::util::json::escape(values[index]) << "\"";
    }
    output << "]";
    return output.str();
}

std::string challenge_json(const domain::AcmeChallenge& challenge) {
    std::map<std::string, std::string> values {
        {"type", "\"" + infrastructure::util::json::escape(challenge.type) + "\""},
        {"url", "\"" + infrastructure::util::json::escape(challenge.url) + "\""},
        {"status", "\"" + infrastructure::util::json::escape(challenge.status) + "\""},
        {"token", "\"" + infrastructure::util::json::escape(challenge.token) + "\""}
    };
    if (!challenge.validated_at.empty()) {
        values["validated"] = "\"" + infrastructure::util::json::escape(challenge.validated_at) + "\"";
    }
    return infrastructure::util::json::object(values);
}

std::string authorization_json(const domain::AcmeAuthorization& authorization) {
    std::ostringstream challenges;
    challenges << "[";
    for (std::size_t index = 0; index < authorization.challenges.size(); ++index) {
        if (index > 0) {
            challenges << ",";
        }
        challenges << challenge_json(authorization.challenges[index]);
    }
    challenges << "]";

    return infrastructure::util::json::object({
        {"status", "\"" + infrastructure::util::json::escape(authorization.status) + "\""},
        {"expires", "\"" + infrastructure::util::json::escape(authorization.expires_at) + "\""},
        {"identifier", "{\"type\":\"" + infrastructure::util::json::escape(authorization.identifier_type) +
            "\",\"value\":\"" + infrastructure::util::json::escape(authorization.identifier_value) + "\"}"},
        {"challenges", challenges.str()}
    });
}

std::string order_json(const domain::AcmeOrder& order, const std::string& base_url) {
    std::ostringstream authzs;
    authzs << "[";
    for (std::size_t index = 0; index < order.authorization_ids.size(); ++index) {
        if (index > 0) {
            authzs << ",";
        }
        authzs << "\"" << infrastructure::util::json::escape(base_url + "/acme/authz/" + order.authorization_ids[index]) << "\"";
    }
    authzs << "]";

    std::ostringstream identifiers;
    identifiers << "[";
    for (std::size_t index = 0; index < order.identifiers.size(); ++index) {
        if (index > 0) {
            identifiers << ",";
        }
        identifiers << "{\"type\":\"" << infrastructure::util::json::escape(order.identifiers[index].type)
                    << "\",\"value\":\"" << infrastructure::util::json::escape(order.identifiers[index].value) << "\"}";
    }
    identifiers << "]";

    std::string certificate_value = "null";
    if (!order.certificate_url.empty()) {
        certificate_value = "\"" + infrastructure::util::json::escape(order.certificate_url) + "\"";
    }

    return infrastructure::util::json::object({
        {"status", "\"" + infrastructure::util::json::escape(order.status) + "\""},
        {"expires", "\"" + infrastructure::util::json::escape(order.expires_at) + "\""},
        {"identifiers", identifiers.str()},
        {"authorizations", authzs.str()},
        {"finalize", "\"" + infrastructure::util::json::escape(order.finalize_url) + "\""},
        {"certificate", certificate_value}
    });
}

domain::NewAccountRequest parse_new_account_payload(const infrastructure::util::AcmeJwsEnvelope& jws) {
    using infrastructure::util::json::find_bool;
    using infrastructure::util::json::find_object;
    using infrastructure::util::json::find_string;
    using infrastructure::util::json::find_string_array;

    if (!jws.jwk_json.has_value()) {
        throw std::runtime_error("newAccount must use jwk in protected header");
    }

    const auto tos = find_bool(jws.payload_json, "termsOfServiceAgreed");
    const auto eab_object = find_object(jws.payload_json, "externalAccountBinding");
    if (!eab_object.has_value()) {
        throw std::runtime_error("external account binding is required");
    }

    const auto eab_protected_b64 = find_string(*eab_object, "protected");
    const auto eab_payload_b64 = find_string(*eab_object, "payload");
    const auto eab_signature = find_string(*eab_object, "signature");
    if (!eab_protected_b64.has_value() || !eab_payload_b64.has_value() || !eab_signature.has_value()) {
        throw std::runtime_error("invalid externalAccountBinding");
    }

    const auto eab_protected_json = infrastructure::util::base64url_decode(*eab_protected_b64);
    const auto eab_payload_json = infrastructure::util::base64url_decode(*eab_payload_b64);
    const auto kid = find_string(eab_protected_json, "kid");
    const auto alg = find_string(eab_protected_json, "alg");
    if (!kid.has_value()) {
        throw std::runtime_error("externalAccountBinding kid missing");
    }

    return {
        .contacts = find_string_array(jws.payload_json, "contact"),
        .terms_of_service_agreed = tos.value_or(false),
        .account_public_jwk = *jws.jwk_json,
        .external_account_binding = domain::ExternalAccountBindingPayload{
            .key_identifier = *kid,
            .protected_jwk = eab_payload_json,
            .protected_header_b64 = *eab_protected_b64,
            .payload_b64 = *eab_payload_b64,
            .signature = *eab_signature,
            .algorithm = alg.value_or("HS256"),
        },
    };
}

std::string account_json(const domain::AcmeAccount& account, const std::string& base_url) {
    return infrastructure::util::json::object({
        {"status", "\"valid\""},
        {"contact", json_string_array(account.contacts)},
        {"orders", "\"" + infrastructure::util::json::escape(base_url + "/acme/account/" + account.account_id + "/orders") + "\""}
    });
}

std::string orders_list_json(const std::vector<domain::AcmeOrder>& orders, const std::string& base_url) {
    std::ostringstream body;
    body << "{\"orders\":[";
    for (std::size_t index = 0; index < orders.size(); ++index) {
        if (index > 0) {
            body << ",";
        }
        body << "\"" << infrastructure::util::json::escape(base_url + "/acme/order/" + orders[index].order_id) << "\"";
    }
    body << "]}";
    return body.str();
}

}  // namespace

AcmeHttpServer::AcmeHttpServer(
    ServerOptions options,
    application::NonceService& nonce_service,
    const application::AcmeAccountService& account_service,
    const application::AcmeWorkflowService& workflow_service)
    : options_(std::move(options)),
      nonce_service_(nonce_service),
      account_service_(account_service),
      workflow_service_(workflow_service) {}

void AcmeHttpServer::run() const {
    const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        throw std::runtime_error("failed to create server socket");
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(static_cast<uint16_t>(options_.port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        close(server_fd);
        throw std::runtime_error("failed to bind server socket");
    }
    if (listen(server_fd, 16) < 0) {
        close(server_fd);
        throw std::runtime_error("failed to listen on server socket");
    }

    std::cout << "ACME HTTP server listening on " << options_.host << ":" << options_.port << "\n";

    while (true) {
        sockaddr_in client_address {};
        socklen_t client_length = sizeof(client_address);
        const int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_address), &client_length);
        if (client_fd < 0) {
            continue;
        }

        std::string request;
        std::array<char, 4096> buffer {};
        ssize_t bytes_read = 0;
        while ((bytes_read = recv(client_fd, buffer.data(), buffer.size(), 0)) > 0) {
            request.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            if (request.find("\r\n\r\n") != std::string::npos) {
                const auto content_length_pos = request.find("Content-Length:");
                if (content_length_pos == std::string::npos) {
                    break;
                }
                const auto length_start = request.find_first_of("0123456789", content_length_pos);
                const auto length_end = request.find("\r\n", content_length_pos);
                const auto length_text = request.substr(length_start, length_end - length_start);
                const auto body_start = request.find("\r\n\r\n");
                const auto expected_size = body_start + 4 + static_cast<std::size_t>(std::stoi(length_text));
                if (request.size() >= expected_size) {
                    break;
                }
            }
        }

        const auto http_response = handle_request(request);
        send(client_fd, http_response.data(), http_response.size(), 0);
        close(client_fd);
    }
}

std::string AcmeHttpServer::handle_request(const std::string& raw_request) const {
    using infrastructure::util::account_id_from_kid;
    using infrastructure::util::der_base64url_to_pem_csr;
    using infrastructure::util::json::escape;
    using infrastructure::util::json::find_string;
    using infrastructure::util::parse_acme_jws;
    using infrastructure::util::parse_order_identifiers;

    try {
        const auto request = parse_request(raw_request);

        if (request.method == "GET" && request.path == "/healthz") {
            return response(200, R"({"status":"ok"})", {{"Content-Type", "application/json"}});
        }

        if (request.method == "GET" && request.path == "/acme/directory") {
            const auto body = infrastructure::util::json::object({
                {"newNonce", "\"" + escape(options_.base_url + "/acme/newNonce") + "\""},
                {"newAccount", "\"" + escape(options_.base_url + "/acme/newAccount") + "\""},
                {"newOrder", "\"" + escape(options_.base_url + "/acme/newOrder") + "\""},
                {"meta", "{\"externalAccountRequired\":true}"}
            });
            return response(200, body, {{"Content-Type", "application/json"}});
        }

        if ((request.method == "HEAD" || request.method == "GET") && request.path == "/acme/newNonce") {
            const auto nonce = nonce_service_.issue_nonce();
            const auto body = request.method == "HEAD" ? "" : "{}";
            return response(
                request.method == "HEAD" ? 204 : 200,
                body,
                {
                    {"Replay-Nonce", nonce},
                    {"Cache-Control", "no-store"},
                    {"Content-Type", "application/json"}
                });
        }

        if (request.method != "POST") {
            return response(405, R"({"type":"malformed","detail":"method not allowed"})", {{"Content-Type", "application/json"}});
        }

        const auto jws = parse_acme_jws(request.body);
        if (jws.nonce.has_value() && !nonce_service_.consume_nonce(*jws.nonce)) {
            throw std::runtime_error("badNonce");
        }
        if (jws.url.has_value() && *jws.url != options_.base_url + request.path) {
            throw std::runtime_error("JWS url does not match request URL");
        }

        std::map<std::string, std::string> headers {
            {"Content-Type", "application/json"},
            {"Replay-Nonce", nonce_service_.issue_nonce()}
        };

        if (request.path == "/acme/newAccount") {
            const auto account_request = parse_new_account_payload(jws);
            const auto registered = account_service_.register_account(account_request);
            const auto account = workflow_service_.get_account(registered.account_id);
            if (!account.has_value()) {
                throw std::runtime_error("failed to load registered account");
            }
            headers["Location"] = options_.base_url + "/acme/acct/" + registered.account_id;
            return response(registered.created ? 201 : 200, account_json(*account, options_.base_url), headers);
        }

        if (request.path == "/acme/newOrder") {
            if (!jws.kid.has_value()) {
                throw std::runtime_error("newOrder requires kid");
            }
            std::vector<domain::Identifier> identifiers;
            for (const auto& item : parse_order_identifiers(jws.payload_json)) {
                const auto separator = item.find('|');
                identifiers.push_back({.type = item.substr(0, separator), .value = item.substr(separator + 1)});
            }
            const auto order = workflow_service_.create_order(account_id_from_kid(*jws.kid), identifiers);
            headers["Location"] = options_.base_url + "/acme/order/" + order.order_id;
            return response(201, order_json(order, options_.base_url), headers);
        }

        if (const auto account_id = path_param(request.path, "/acme/acct/"); account_id.has_value()) {
            const auto account = workflow_service_.get_account(*account_id);
            if (!account.has_value()) {
                return response(404, R"({"type":"notFound","detail":"account not found"})", headers);
            }
            return response(200, account_json(*account, options_.base_url), headers);
        }

        if (const auto account_id = path_param(request.path, "/acme/account/", "/orders"); account_id.has_value()) {
            return response(200, orders_list_json(workflow_service_.get_account_orders(*account_id), options_.base_url), headers);
        }

        if (const auto order_id = path_param(request.path, "/acme/order/", "/finalize"); order_id.has_value()) {
            if (!jws.kid.has_value()) {
                throw std::runtime_error("finalize requires kid");
            }
            const auto csr_b64 = find_string(jws.payload_json, "csr");
            if (!csr_b64.has_value()) {
                throw std::runtime_error("csr is required");
            }
            const auto order = workflow_service_.finalize_order(*order_id, account_id_from_kid(*jws.kid), der_base64url_to_pem_csr(*csr_b64));
            return response(200, order_json(order, options_.base_url), headers);
        }

        if (const auto order_id = path_param(request.path, "/acme/order/"); order_id.has_value()) {
            const auto order = workflow_service_.get_order(*order_id);
            if (!order.has_value()) {
                return response(404, R"({"type":"notFound","detail":"order not found"})", headers);
            }
            return response(200, order_json(*order, options_.base_url), headers);
        }

        if (const auto authz_id = path_param(request.path, "/acme/authz/"); authz_id.has_value()) {
            const auto authz = workflow_service_.get_authorization(*authz_id);
            if (!authz.has_value()) {
                return response(404, R"({"type":"notFound","detail":"authorization not found"})", headers);
            }
            return response(200, authorization_json(*authz), headers);
        }

        if (const auto challenge_id = path_param(request.path, "/acme/challenge/"); challenge_id.has_value()) {
            const auto authorization = workflow_service_.get_authorization_by_challenge(*challenge_id);
            if (!authorization.has_value()) {
                return response(404, R"({"type":"notFound","detail":"challenge not found"})", headers);
            }
            headers["Link"] = "<" + options_.base_url + "/acme/authz/" + authorization->authorization_id + ">;rel=\"up\"";
            if (request.method == "POST") {
                if (!jws.kid.has_value()) {
                    throw std::runtime_error("challenge acknowledgement requires kid");
                }
                const auto challenge = workflow_service_.acknowledge_challenge(*challenge_id, account_id_from_kid(*jws.kid));
                return response(200, challenge_json(challenge), headers);
            }
            if (jws.payload_json.empty() || jws.payload_json == "{}") {
                const auto challenge = workflow_service_.get_challenge(*challenge_id);
                if (!challenge.has_value()) {
                    return response(404, R"({"type":"notFound","detail":"challenge not found"})", headers);
                }
                return response(200, challenge_json(*challenge), headers);
            }
        }

        if (const auto certificate_id = path_param(request.path, "/acme/certificate/"); certificate_id.has_value()) {
            const auto certificate = workflow_service_.get_certificate(*certificate_id);
            if (!certificate.has_value()) {
                return response(404, R"({"type":"notFound","detail":"certificate not found"})", headers);
            }
            return response(200, certificate->pem_chain, {{"Content-Type", "application/pem-certificate-chain"}, {"Replay-Nonce", nonce_service_.issue_nonce()}});
        }

        return response(404, R"({"type":"notFound","detail":"endpoint not found"})", headers);
    } catch (const std::exception& ex) {
        return response(
            400,
            std::string("{\"type\":\"malformed\",\"detail\":\"") + infrastructure::util::json::escape(ex.what()) + "\"}",
            {{"Content-Type", "application/json"}, {"Replay-Nonce", nonce_service_.issue_nonce()}});
    }
}

}  // namespace acme::infrastructure::transport
