#include "infrastructure/file_acme_order_repository.h"

#include <filesystem>

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

namespace {

std::string join_encoded(const std::vector<std::string>& values) {
    std::string result;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            result += ",";
        }
        result += util::base64url_encode(values[index]);
    }
    return result;
}

std::vector<std::string> split_decoded(const std::string& value) {
    std::vector<std::string> items;
    for (const auto& part : util::split(value, ',')) {
        if (!part.empty()) {
            items.push_back(util::base64url_decode(part));
        }
    }
    return items;
}

}  // namespace

FileAcmeOrderRepository::FileAcmeOrderRepository(std::string data_dir) : data_dir_(std::move(data_dir)) {}

domain::AcmeOrder FileAcmeOrderRepository::save(const domain::AcmeOrder& order) {
    return update(order);
}

domain::AcmeOrder FileAcmeOrderRepository::update(const domain::AcmeOrder& order) {
    util::write_lines(
        path_for(order.order_id),
        {
            "order_id=" + util::base64url_encode(order.order_id),
            "account_id=" + util::base64url_encode(order.account_id),
            "status=" + util::base64url_encode(order.status),
            "expires_at=" + util::base64url_encode(order.expires_at),
            "finalize_url=" + util::base64url_encode(order.finalize_url),
            "certificate_id=" + util::base64url_encode(order.certificate_id),
            "certificate_url=" + util::base64url_encode(order.certificate_url),
            "csr_pem=" + util::base64url_encode(order.csr_pem),
            "authorization_ids=" + join_encoded(order.authorization_ids),
            "identifiers=" + join_encoded(encode_identifiers(order.identifiers)),
        });
    return order;
}

std::optional<domain::AcmeOrder> FileAcmeOrderRepository::find_by_id(const std::string& order_id) const {
    const auto lines = util::read_lines(path_for(order_id));
    if (lines.empty()) {
        return std::nullopt;
    }

    domain::AcmeOrder order;
    for (const auto& line : lines) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "order_id") {
            order.order_id = util::base64url_decode(value);
        } else if (key == "account_id") {
            order.account_id = util::base64url_decode(value);
        } else if (key == "status") {
            order.status = util::base64url_decode(value);
        } else if (key == "expires_at") {
            order.expires_at = util::base64url_decode(value);
        } else if (key == "finalize_url") {
            order.finalize_url = util::base64url_decode(value);
        } else if (key == "certificate_id") {
            order.certificate_id = util::base64url_decode(value);
        } else if (key == "certificate_url") {
            order.certificate_url = util::base64url_decode(value);
        } else if (key == "csr_pem") {
            order.csr_pem = util::base64url_decode(value);
        } else if (key == "authorization_ids") {
            order.authorization_ids = split_decoded(value);
        } else if (key == "identifiers") {
            order.identifiers = decode_identifiers(split_decoded(value));
        }
    }
    return order;
}

std::vector<domain::AcmeOrder> FileAcmeOrderRepository::find_by_account_id(const std::string& account_id) const {
    std::vector<domain::AcmeOrder> orders;
    const auto directory = std::filesystem::path(data_dir_ + "/orders");
    if (!std::filesystem::exists(directory)) {
        return orders;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto order = find_by_id(entry.path().stem().string());
        if (order.has_value() && order->account_id == account_id) {
            orders.push_back(*order);
        }
    }
    return orders;
}

std::string FileAcmeOrderRepository::path_for(const std::string& order_id) const {
    return data_dir_ + "/orders/" + order_id + ".record";
}

std::vector<std::string> FileAcmeOrderRepository::encode_identifiers(
    const std::vector<domain::Identifier>& identifiers) {
    std::vector<std::string> lines;
    for (const auto& identifier : identifiers) {
        lines.push_back(identifier.type + "|" + identifier.value);
    }
    return lines;
}

std::vector<domain::Identifier> FileAcmeOrderRepository::decode_identifiers(const std::vector<std::string>& lines) {
    std::vector<domain::Identifier> identifiers;
    for (const auto& line : lines) {
        const auto separator = line.find('|');
        if (separator == std::string::npos) {
            continue;
        }
        identifiers.push_back({
            .type = line.substr(0, separator),
            .value = line.substr(separator + 1),
        });
    }
    return identifiers;
}

}  // namespace acme::infrastructure
