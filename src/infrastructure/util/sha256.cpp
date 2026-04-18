#include "infrastructure/util/sha256.h"

#include <CommonCrypto/CommonDigest.h>

#include "infrastructure/util/base64url.h"

namespace acme::infrastructure::util {

std::string sha256_base64url(const std::string& payload) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payload.data(), static_cast<CC_LONG>(payload.size()), digest);
    return base64url_encode(std::string(reinterpret_cast<const char*>(digest), CC_SHA256_DIGEST_LENGTH));
}

}  // namespace acme::infrastructure::util
