#include "infrastructure/file_acme_account_repository.h"

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

FileAcmeAccountRepository::FileAcmeAccountRepository(std::string file_path) : file_path_(std::move(file_path)) {}

std::optional<domain::AcmeAccount> FileAcmeAccountRepository::find_by_public_jwk(const std::string& jwk) const {
    for (const auto& account : load_all()) {
        if (account.account_public_jwk == jwk) {
            return account;
        }
    }
    return std::nullopt;
}

domain::AcmeAccount FileAcmeAccountRepository::save(const domain::AcmeAccount& account) {
    auto accounts = load_all();
    bool replaced = false;
    for (auto& existing : accounts) {
        if (existing.account_id == account.account_id) {
            existing = account;
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        accounts.push_back(account);
    }

    std::vector<std::string> lines;
    for (const auto& item : accounts) {
        std::string contacts_line;
        for (std::size_t index = 0; index < item.contacts.size(); ++index) {
            if (index > 0) {
                contacts_line += ",";
            }
            contacts_line += util::base64url_encode(item.contacts[index]);
        }

        lines.push_back(
            item.account_id + "\t" +
            util::base64url_encode(item.account_public_jwk) + "\t" +
            util::base64url_encode(item.bound_client_id) + "\t" +
            util::base64url_encode(item.ca_name) + "\t" +
            contacts_line);
    }

    util::write_lines(file_path_, lines);
    return account;
}

std::optional<domain::AcmeAccount> FileAcmeAccountRepository::find_by_id(const std::string& account_id) const {
    const auto accounts = load_all();
    for (auto it = accounts.rbegin(); it != accounts.rend(); ++it) {
        if (it->account_id == account_id) {
            return *it;
        }
    }
    return std::nullopt;
}

std::optional<domain::AcmeAccount> FileAcmeAccountRepository::find_by_key_id(const std::string& key_id) const {
    return find_by_id(key_id);
}

std::vector<domain::AcmeAccount> FileAcmeAccountRepository::load_all() const {
    const auto lines = util::read_lines(file_path_);
    std::vector<domain::AcmeAccount> accounts;
    for (const auto& line : lines) {
        if (line.empty()) {
            continue;
        }
        const auto parts = util::split(line, '\t');
        if (parts.size() != 5) {
            continue;
        }

        std::vector<std::string> contacts;
        for (const auto& encoded : util::split(parts[4], ',')) {
            if (!encoded.empty()) {
                contacts.push_back(util::base64url_decode(encoded));
            }
        }

        accounts.push_back({
            .account_id = parts[0],
            .contacts = contacts,
            .account_public_jwk = util::base64url_decode(parts[1]),
            .bound_client_id = util::base64url_decode(parts[2]),
            .ca_name = util::base64url_decode(parts[3]),
        });
    }
    return accounts;
}

}  // namespace acme::infrastructure
