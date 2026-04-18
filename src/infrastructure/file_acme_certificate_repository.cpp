#include "infrastructure/file_acme_certificate_repository.h"

#include "infrastructure/util/base64url.h"
#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

FileAcmeCertificateRepository::FileAcmeCertificateRepository(std::string data_dir) : data_dir_(std::move(data_dir)) {}

domain::AcmeCertificate FileAcmeCertificateRepository::save(const domain::AcmeCertificate& certificate) {
    util::write_lines(
        path_for(certificate.certificate_id),
        {
            "certificate_id=" + util::base64url_encode(certificate.certificate_id),
            "order_id=" + util::base64url_encode(certificate.order_id),
            "pem_chain=" + util::base64url_encode(certificate.pem_chain),
            "leaf_pem=" + util::base64url_encode(certificate.leaf_pem),
            "issued_at=" + util::base64url_encode(certificate.issued_at),
            "serial_hex=" + util::base64url_encode(certificate.serial_hex),
        });
    return certificate;
}

std::optional<domain::AcmeCertificate> FileAcmeCertificateRepository::find_by_id(
    const std::string& certificate_id) const {
    const auto lines = util::read_lines(path_for(certificate_id));
    if (lines.empty()) {
        return std::nullopt;
    }

    domain::AcmeCertificate certificate;
    for (const auto& line : lines) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "certificate_id") {
            certificate.certificate_id = util::base64url_decode(value);
        } else if (key == "order_id") {
            certificate.order_id = util::base64url_decode(value);
        } else if (key == "pem_chain") {
            certificate.pem_chain = util::base64url_decode(value);
        } else if (key == "leaf_pem") {
            certificate.leaf_pem = util::base64url_decode(value);
        } else if (key == "issued_at") {
            certificate.issued_at = util::base64url_decode(value);
        } else if (key == "serial_hex") {
            certificate.serial_hex = util::base64url_decode(value);
        }
    }
    return certificate;
}

std::string FileAcmeCertificateRepository::path_for(const std::string& certificate_id) const {
    return data_dir_ + "/certificates/" + certificate_id + ".record";
}

}  // namespace acme::infrastructure
