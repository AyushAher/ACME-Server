#include "infrastructure/postgres_client.h"

#include <stdexcept>

#include "infrastructure/util/file_store.h"

namespace acme::infrastructure {

PostgresClient::PostgresClient(std::string connection_string) {
    connection_ = PQconnectdb(connection_string.c_str());
    if (connection_ == nullptr || PQstatus(connection_) != CONNECTION_OK) {
        const std::string error = connection_ != nullptr ? PQerrorMessage(connection_) : "unknown connection error";
        throw std::runtime_error("failed to connect to PostgreSQL: " + error);
    }
}

PostgresClient::~PostgresClient() {
    if (connection_ != nullptr) {
        PQfinish(connection_);
    }
}

void PostgresClient::exec(const std::string& sql) const {
    PGresult* result = PQexec(connection_, sql.c_str());
    if (result == nullptr) {
        throw std::runtime_error("postgres exec failed");
    }
    const auto status = PQresultStatus(result);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        const std::string error = PQerrorMessage(connection_);
        PQclear(result);
        throw std::runtime_error("postgres exec failed: " + error);
    }
    PQclear(result);
}

std::vector<std::vector<std::string>> PostgresClient::query(const std::string& sql) const {
    PGresult* result = PQexec(connection_, sql.c_str());
    if (result == nullptr) {
        throw std::runtime_error("postgres query failed");
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        const std::string error = PQerrorMessage(connection_);
        PQclear(result);
        throw std::runtime_error("postgres query failed: " + error);
    }

    std::vector<std::vector<std::string>> rows;
    const auto row_count = PQntuples(result);
    const auto col_count = PQnfields(result);
    for (int row = 0; row < row_count; ++row) {
        std::vector<std::string> values;
        for (int col = 0; col < col_count; ++col) {
            values.emplace_back(PQgetvalue(result, row, col));
        }
        rows.push_back(std::move(values));
    }
    PQclear(result);
    return rows;
}

std::string PostgresClient::escape_literal(const std::string& value) const {
    char* escaped = PQescapeLiteral(connection_, value.c_str(), value.size());
    if (escaped == nullptr) {
        throw std::runtime_error("failed to escape postgres literal");
    }
    const std::string result(escaped);
    PQfreemem(escaped);
    return result;
}

void PostgresClient::ensure_schema(const std::string& schema_sql_path) const {
    std::string schema;
    for (const auto& line : util::read_lines(schema_sql_path)) {
        schema += line + "\n";
    }
    exec(schema);
}

}  // namespace acme::infrastructure
