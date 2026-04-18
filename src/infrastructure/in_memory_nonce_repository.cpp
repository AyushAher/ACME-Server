#include "infrastructure/in_memory_nonce_repository.h"

namespace acme::infrastructure {

std::string InMemoryNonceRepository::issue() {
    const auto nonce = "nonce-" + std::to_string(counter_++);
    live_nonces_.insert(nonce);
    return nonce;
}

bool InMemoryNonceRepository::consume(const std::string& nonce) {
    return live_nonces_.erase(nonce) == 1;
}

}  // namespace acme::infrastructure
