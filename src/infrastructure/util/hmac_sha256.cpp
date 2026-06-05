#include "infrastructure/util/hmac_sha256.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <string>

#include "infrastructure/util/base64url.h"

namespace acme::infrastructure::util {

std::string hmac_sha256_base64url(const std::string& key, const std::string& payload) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(),
         key.data(),
         static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(payload.data()),
         payload.size(),
         digest,
         nullptr);

    return base64url_encode(std::string(
        reinterpret_cast<const char*>(digest),
        SHA256_DIGEST_LENGTH));
}

}  // namespace acme::infrastructure::util
