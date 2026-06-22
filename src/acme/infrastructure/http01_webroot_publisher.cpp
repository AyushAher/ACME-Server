#include "acme/infrastructure/http01_webroot_publisher.h"

#include <fstream>

#include "acme/infrastructure/util/file_store.h"

namespace acme::infrastructure
{

    Http01WebrootPublisher::Http01WebrootPublisher(std::string webroot)
        : webroot_(std::move(webroot)) {}

    bool Http01WebrootPublisher::configured() const
    {
        return !webroot_.empty();
    }

    domain::CertificateIssueResult Http01WebrootPublisher::publish(
        const std::string &token,
        const std::string &key_authorization) const
    {
        if (!configured())
        {
            return {
                .error = "http01_challenge_webroot is not configured in server.conf",
            };
        }

        const auto path = webroot_ + "/.well-known/acme-challenge/" + token;
        try
        {
            util::ensure_parent_directory(path);
            std::ofstream output(path, std::ios::trunc | std::ios::binary);
            if (!output.is_open())
            {
                return {.error = "unable to write http-01 challenge file: " + path};
            }
            output << key_authorization;
        }
        catch (const std::exception &ex)
        {
            return {.error = std::string("http-01 webroot publish failed: ") + ex.what()};
        }

        return {.success = true};
    }

} // namespace acme::infrastructure
