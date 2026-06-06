#pragma once

#include <string>

namespace common
{
    struct ServerOptions
    {
        std::string host;
        int port{8080};
        std::string base_url;
    };
} // namespace common