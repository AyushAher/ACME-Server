#include "acme/infrastructure/shell_http_client.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <sstream>

namespace acme::infrastructure
{

    HttpResponse ShellHttpClient::execute(const HttpRequest &request) const
    {
        std::ostringstream command;
        command << "curl -s -i -X " << shell_escape(request.method) << " ";

        if (request.insecure_skip_tls_verify)
        {
            command << "-k ";
        }

        for (const auto &[header_name, header_value] : request.headers)
        {
            command << "-H " << shell_escape(header_name + ": " + header_value) << " ";
        }

        if (request.client_pkcs12_bundle.has_value())
        {
            command << "--cert-type P12 --cert "
                    << shell_escape(
                           *request.client_pkcs12_bundle + ":" + request.client_pkcs12_password.value_or(""))
                    << " ";
        }

        if (!request.body.empty())
        {
            command << "--data " << shell_escape(request.body) << " ";
        }

        command << "-w '\\n%{http_code}' " << shell_escape(request.url);

        std::array<char, 512> buffer{};
        std::string output;
        if (FILE *pipe = popen(command.str().c_str(), "r"))
        {
            while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr)
            {
                output += buffer.data();
            }
            pclose(pipe);
        }
        else
        {
            return {.error = "failed to launch curl"};
        }

        const auto separator = output.find_last_of('\n');
        if (separator == std::string::npos)
        {
            return {.error = "unable to parse HTTP response from curl"};
        }

        auto response_text = output.substr(0, separator);
        const auto code_text = output.substr(separator + 1);
        std::map<std::string, std::string> headers;
        std::string body = response_text;

        const auto header_separator = response_text.rfind("\r\n\r\n");
        if (header_separator != std::string::npos)
        {
            auto header_text = response_text.substr(0, header_separator);
            body = response_text.substr(header_separator + 4);
            const auto last_status = header_text.rfind("HTTP/");
            if (last_status != std::string::npos)
            {
                header_text = header_text.substr(last_status);
            }

            std::istringstream header_stream(header_text);
            std::string line;
            std::getline(header_stream, line);
            while (std::getline(header_stream, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                const auto colon = line.find(':');
                if (colon == std::string::npos)
                {
                    continue;
                }
                auto name = line.substr(0, colon);
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });
                auto value = line.substr(colon + 1);
                while (!value.empty() && value.front() == ' ')
                {
                    value.erase(value.begin());
                }
                headers[name] = value;
            }
        }

        try
        {
            return {.status_code = std::stoi(code_text), .headers = std::move(headers), .body = body};
        }
        catch (...)
        {
            return {.body = body, .error = "invalid HTTP status code returned by curl"};
        }
    }

    std::string ShellHttpClient::shell_escape(const std::string &value)
    {
        std::string escaped = "'";
        for (const auto ch : value)
        {
            if (ch == '\'')
            {
                escaped += "'\\''";
            }
            else
            {
                escaped.push_back(ch);
            }
        }
        escaped += "'";
        return escaped;
    }

} // namespace acme::infrastructure
