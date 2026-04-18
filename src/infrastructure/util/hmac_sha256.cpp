#include "infrastructure/util/hmac_sha256.h"

#include <CommonCrypto/CommonHMAC.h>

#include <string>

#include "infrastructure/util/base64url.h"

namespace acme::infrastructure::util {

std::string hmac_sha256_base64url(const std::string& key, const std::string& payload) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           key.data(),
           key.size(),
           payload.data(),
           payload.size(),
           digest);

    return base64url_encode(std::string(
        reinterpret_cast<const char*>(digest),
        CC_SHA256_DIGEST_LENGTH));
}

}  // namespace acme::infrastructure::util
