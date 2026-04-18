#include "application/nonce_service.h"

namespace acme::application {

NonceService::NonceService(NonceRepository& repository) : repository_(repository) {}

std::string NonceService::issue_nonce() {
    return repository_.issue();
}

bool NonceService::consume_nonce(const std::string& nonce) {
    return repository_.consume(nonce);
}

}  // namespace acme::application
