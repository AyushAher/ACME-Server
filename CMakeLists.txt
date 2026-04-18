cmake_minimum_required(VERSION 3.16)

project(acme_server_demo VERSION 1.0 LANGUAGES CXX)

# =========================
# Compiler Configuration
# =========================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optional: force clang
set(CMAKE_CXX_COMPILER clang++)

# =========================
# libpq (PostgreSQL)
# =========================
set(LIBPQ_PREFIX /opt/homebrew/opt/libpq)

include_directories(${LIBPQ_PREFIX}/include)
link_directories(${LIBPQ_PREFIX}/lib)

# =========================
# Core Library
# =========================
add_library(acme_core

    # -------- application --------
    src/application/acme_workflow_service.cpp
    src/application/acme_account_service.cpp
    src/application/certificate_order_service.cpp
    src/application/eab_service.cpp
    src/application/nonce_service.cpp

    # -------- infrastructure --------
    src/infrastructure/config/app_config.cpp
    src/infrastructure/ejbca_certificate_authority.cpp
    src/infrastructure/file_acme_authorization_repository.cpp
    src/infrastructure/file_acme_account_repository.cpp
    src/infrastructure/file_acme_certificate_repository.cpp
    src/infrastructure/file_eab_mapping_repository.cpp
    src/infrastructure/file_acme_order_repository.cpp
    src/infrastructure/file_nonce_repository.cpp
    src/infrastructure/http01_challenge_validator.cpp
    src/infrastructure/in_memory_acme_account_repository.cpp
    src/infrastructure/in_memory_eab_mapping_repository.cpp
    src/infrastructure/in_memory_nonce_repository.cpp
    src/infrastructure/openssl_certificate_authority.cpp

    # ✅ postgres (missing before)
    src/infrastructure/postgres_client.cpp
    src/infrastructure/postgres_repositories.cpp
    src/infrastructure/postgres_serialization.cpp

    src/infrastructure/shell_http_client.cpp
    src/infrastructure/transport/acme_http_server.cpp

    # -------- utilities --------
    src/infrastructure/util/acme_protocol.cpp
    src/infrastructure/util/base64url.cpp
    src/infrastructure/util/command_runner.cpp
    src/infrastructure/util/file_store.cpp
    src/infrastructure/util/json.cpp
    src/infrastructure/util/hmac_sha256.cpp
    src/infrastructure/util/random.cpp
    src/infrastructure/util/sha256.cpp
)

target_include_directories(acme_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${LIBPQ_PREFIX}/include
)

target_compile_options(acme_core PRIVATE
    -Wall -Wextra -Wpedantic
)

# =========================
# Dependencies
# =========================
find_package(OpenSSL REQUIRED)

target_link_libraries(acme_core
    OpenSSL::Crypto
    OpenSSL::SSL
    pq   # 🔥 libpq
)

# =========================
# Main Executable
# =========================
add_executable(acme_server_demo
    src/main.cpp
)

target_link_libraries(acme_server_demo
    acme_core
)

# =========================
# Test Executable
# =========================
add_executable(test_acme_server
    tests/test_main.cpp
)

target_link_libraries(test_acme_server
    acme_core
)

# =========================
# Testing
# =========================
enable_testing()

add_test(
    NAME acme_tests
    COMMAND test_acme_server
)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")