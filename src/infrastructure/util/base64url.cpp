#include "infrastructure/util/base64url.h"

#include <array>

namespace acme::infrastructure::util {

std::string base64url_encode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string output;
    int val = 0;
    int valb = -6;
    for (const auto ch : input) {
        val = (val << 8) + static_cast<unsigned char>(ch);
        valb += 8;
        while (valb >= 0) {
            output.push_back(kAlphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        output.push_back(kAlphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    return output;
}

std::string base64url_decode(const std::string& input) {
    std::array<int, 256> reverse {};
    reverse.fill(-1);

    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (std::size_t index = 0; index < alphabet.size(); ++index) {
        reverse[static_cast<unsigned char>(alphabet[index])] = static_cast<int>(index);
    }

    std::string output;
    int val = 0;
    int valb = -8;
    for (const auto ch : input) {
        const auto decoded = reverse[static_cast<unsigned char>(ch)];
        if (decoded == -1) {
            continue;
        }
        val = (val << 6) + decoded;
        valb += 6;
        if (valb >= 0) {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

}  // namespace acme::infrastructure::util
