#pragma once

#include <string>

namespace acme::domain {

struct EabMapping {
    std::string id;
    std::string client_id;
    std::string hmac_key;
    std::string ca;
    std::string credentials_id;
};

}  // namespace acme::domain
