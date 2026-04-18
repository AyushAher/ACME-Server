#pragma once

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

namespace acme::infrastructure {

class PostgresClient {
  public:
    explicit PostgresClient(std::string connection_string);
    ~PostgresClient();

    PostgresClient(const PostgresClient&) = delete;
    PostgresClient& operator=(const PostgresClient&) = delete;

    void exec(const std::string& sql) const;
    std::vector<std::vector<std::string>> query(const std::string& sql) const;
    std::string escape_literal(const std::string& value) const;
    void ensure_schema(const std::string& schema_sql_path) const;

  private:
    PGconn* connection_ {nullptr};
};

}  // namespace acme::infrastructure
