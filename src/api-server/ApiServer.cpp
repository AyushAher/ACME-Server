#include "api-server/ApiServer.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include "common/server_options.h"
#include "acme/infrastructure/util/acme_protocol.h"
#include "acme/infrastructure/util/base64url.h"
#include "acme/infrastructure/util/json.h"

namespace api_server
{
    namespace
    {

        struct ParsedRequest
        {
            std::string method;
            std::string path;
            std::map<std::string, std::string> headers;
            std::string body;
        };

        ParsedRequest parse_request(const std::string &raw)
        {
            ParsedRequest request;
            const auto header_end = raw.find("\r\n\r\n");
            const auto head = raw.substr(0, header_end);
            request.body = header_end == std::string::npos ? "" : raw.substr(header_end + 4);

            std::istringstream stream(head);
            std::string request_line;
            std::getline(stream, request_line);
            if (!request_line.empty() && request_line.back() == '\r')
            {
                request_line.pop_back();
            }

            std::istringstream request_line_stream(request_line);
            request_line_stream >> request.method >> request.path;

            std::string header_line;
            while (std::getline(stream, header_line))
            {
                if (!header_line.empty() && header_line.back() == '\r')
                {
                    header_line.pop_back();
                }
                const auto separator = header_line.find(':');
                if (separator == std::string::npos)
                {
                    continue;
                }
                auto value = header_line.substr(separator + 1);
                if (!value.empty() && value.front() == ' ')
                {
                    value.erase(0, 1);
                }
                request.headers[header_line.substr(0, separator)] = value;
            }

            return request;
        }

        std::string reason_phrase(int status)
        {
            switch (status)
            {
            case 200:
                return "OK";
            case 201:
                return "Created";
            case 204:
                return "No Content";
            case 400:
                return "Bad Request";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown";
            }
        }

        std::string response(
            int status,
            const std::string &body,
            const std::map<std::string, std::string> &headers = {})
        {
            std::ostringstream output;
            output << "HTTP/1.1 " << status << " " << reason_phrase(status) << "\r\n";
            for (const auto &[key, value] : headers)
            {
                output << key << ": " << value << "\r\n";
            }
            output << "Content-Length: " << body.size() << "\r\n";
            output << "Connection: close\r\n\r\n";
            output << body;
            return output.str();
        }

        std::optional<std::string> path_param(const std::string &path, const std::string &prefix, const std::string &suffix = "")
        {
            if (!path.starts_with(prefix))
            {
                return std::nullopt;
            }
            auto value = path.substr(prefix.size());
            if (!suffix.empty())
            {
                if (!value.ends_with(suffix))
                {
                    return std::nullopt;
                }
                value = value.substr(0, value.size() - suffix.size());
            }
            if (value.empty() || value.find('/') != std::string::npos)
            {
                return std::nullopt;
            }
            return value;
        }

        std::string json_string_array(const std::vector<std::string> &values)
        {
            std::ostringstream output;
            output << "[";
            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0)
                {
                    output << ",";
                }
                output << "\"" << acme::infrastructure::util::json::escape(values[index]) << "\"";
            }
            output << "]";
            return output.str();
        }

    }

    api_server::ApiServer::ApiServer(
        ServerOptions options,
        acme::infrastructure::transport::AcmeHttpServer &http_server)
        : options_(std::move(options)),
          http_server_(http_server) {}

    void ApiServer::run() const
    {
        const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0)
        {
            throw std::runtime_error("failed to create server socket");
        }

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(static_cast<uint16_t>(options_.port));

        if (bind(server_fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0)
        {
            close(server_fd);
            throw std::runtime_error("failed to bind server socket");
        }
        if (listen(server_fd, 16) < 0)
        {
            close(server_fd);
            throw std::runtime_error("failed to listen on server socket");
        }

        std::cout << "ACME HTTP server listening on " << options_.host << ":" << options_.port << "\n";

        while (true)
        {
            sockaddr_in client_address{};
            socklen_t client_length = sizeof(client_address);
            const int client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&client_address), &client_length);
            if (client_fd < 0)
            {
                continue;
            }

            std::string request;
            std::array<char, 4096> buffer{};
            ssize_t bytes_read = 0;
            while ((bytes_read = recv(client_fd, buffer.data(), buffer.size(), 0)) > 0)
            {
                request.append(buffer.data(), static_cast<std::size_t>(bytes_read));
                if (request.find("\r\n\r\n") != std::string::npos)
                {
                    const auto content_length_pos = request.find("Content-Length:");
                    if (content_length_pos == std::string::npos)
                    {
                        break;
                    }
                    const auto length_start = request.find_first_of("0123456789", content_length_pos);
                    const auto length_end = request.find("\r\n", content_length_pos);
                    const auto length_text = request.substr(length_start, length_end - length_start);
                    const auto body_start = request.find("\r\n\r\n");
                    const auto expected_size = body_start + 4 + static_cast<std::size_t>(std::stoi(length_text));
                    if (request.size() >= expected_size)
                    {
                        break;
                    }
                }
            }

            const auto requestParsed = parse_request(request);
            const auto response = http_server_.handle_request(request);
            send(client_fd, response.data(), response.size(), 0);
            close(client_fd);
        }
    }
}