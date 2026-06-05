#include "infrastructure/util/sha256.h"

#include <openssl/sha.h>

#include "infrastructure/util/base64url.h"

namespace acme::infrastructure::util {

std::string sha256_base64url(const std::string& payload) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest);
    return base64url_encode(std::string(reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH));
}

}  // namespace acme::infrastructure::util
