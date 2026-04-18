#include "infrastructure/util/random.h"

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#include "infrastructure/util/base64url.h"

namespace acme::infrastructure::util {

std::string random_token(std::size_t bytes) {
    std::random_device device;
    std::mt19937 generator(device());
    std::uniform_int_distribution<int> distribution(0, 255);

    std::string raw;
    raw.reserve(bytes);
    for (std::size_t index = 0; index < bytes; ++index) {
        raw.push_back(static_cast<char>(distribution(generator)));
    }
    return base64url_encode(raw);
}

std::string now_rfc3339() {
    const auto now = std::chrono::system_clock::now();
    const auto now_time = std::chrono::system_clock::to_time_t(now);
    std::tm utc_time {};
    gmtime_r(&now_time, &utc_time);
    std::ostringstream output;
    output << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

}  // namespace acme::infrastructure::util
