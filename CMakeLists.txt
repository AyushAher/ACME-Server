cmake_minimum_required(VERSION 3.16)

project(acme_server_demo VERSION 1.0 LANGUAGES CXX)

# ==================================================
# C++ Configuration
# ==================================================

# --- 1. Project Configuration ---
if (WIN32)
    set(CMAKE_CXX_STANDARD 20)
else()
    set(CMAKE_CXX_STANDARD 20)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ==================================================
# Dependencies
# ==================================================

# OpenSSL
find_package(OpenSSL REQUIRED)

set(LIBPQ_PREFIX "/opt/homebrew/opt/libpq")
find_path(LIBPQ_INCLUDE_DIR
    NAMES libpq-fe.h
    HINTS
        ${LIBPQ_PREFIX}/include
        /opt/homebrew/include
        /usr/local/include
)
find_library(LIBPQ_LIBRARY
    NAMES pq libpq
    HINTS
        ${LIBPQ_PREFIX}/lib
        /opt/homebrew/lib
        /usr/local/lib
)

if(NOT LIBPQ_INCLUDE_DIR OR NOT LIBPQ_LIBRARY)
    find_package(PostgreSQL REQUIRED)
    set(LIBPQ_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIRS})
    set(LIBPQ_LIBRARY PostgreSQL::PostgreSQL)
endif()

# PostgreSQL libpq
# find_path(LIBPQ_INCLUDE_DIR
#     NAMES libpq-fe.h
#     PATHS
#         "C:/Program Files/PostgreSQL/18/include"
#         "C:/Program Files/PostgreSQL/17/include"
#         "C:/Program Files/PostgreSQL/16/include"
# )
# find_library(LIBPQ_LIBRARY
#     NAMES libpq
#     PATHS
#         "C:/Program Files/PostgreSQL/18/lib"
#         "C:/Program Files/PostgreSQL/17/lib"
#         "C:/Program Files/PostgreSQL/16/lib"
# )

if(NOT LIBPQ_INCLUDE_DIR)
    message(FATAL_ERROR "PostgreSQL headers (libpq-fe.h) not found")
endif()

if(NOT LIBPQ_LIBRARY)
    message(FATAL_ERROR "PostgreSQL library (libpq.lib) not found")
endif()

message(STATUS "PostgreSQL Include: ${LIBPQ_INCLUDE_DIR}")
message(STATUS "PostgreSQL Library: ${LIBPQ_LIBRARY}")

# ==================================================
# Core Library
# ==================================================

add_library(acme_core

    # ---------- application ----------
    src/acme/application/acme_workflow_service.cpp
    src/acme/application/acme_account_service.cpp
    src/acme/application/certificate_order_service.cpp
    src/acme/application/eab_service.cpp
    src/acme/application/nonce_service.cpp
    src/api-server/ApiServer.cpp
    src/discovery/certificate_discovery_service.cpp

    # ---------- infrastructure ----------
    src/acme/infrastructure/config/app_config.cpp
    src/acme/infrastructure/ejbca_certificate_authority.cpp
    src/acme/infrastructure/file_acme_authorization_repository.cpp
    src/acme/infrastructure/file_acme_account_repository.cpp
    src/acme/infrastructure/file_acme_certificate_repository.cpp
    src/acme/infrastructure/file_eab_mapping_repository.cpp
    src/acme/infrastructure/file_acme_order_repository.cpp
    src/acme/infrastructure/file_nonce_repository.cpp
    src/acme/infrastructure/http01_challenge_validator.cpp
    src/acme/infrastructure/in_memory_acme_account_repository.cpp
    src/acme/infrastructure/in_memory_eab_mapping_repository.cpp
    src/acme/infrastructure/in_memory_nonce_repository.cpp
    src/acme/infrastructure/openssl_certificate_authority.cpp

    # PostgreSQL
    src/acme/infrastructure/postgres_client.cpp
    src/acme/infrastructure/postgres_repositories.cpp
    src/acme/infrastructure/postgres_serialization.cpp

    src/acme/infrastructure/shell_http_client.cpp
    src/acme/infrastructure/transport/acme_http_server.cpp

    # ---------- utilities ----------
    src/acme/infrastructure/util/acme_protocol.cpp
    src/acme/infrastructure/util/base64url.cpp
    src/acme/infrastructure/util/command_runner.cpp
    src/acme/infrastructure/util/file_store.cpp
    src/acme/infrastructure/util/json.cpp
    src/acme/infrastructure/util/hmac_sha256.cpp
    src/acme/infrastructure/util/random.cpp
    src/acme/infrastructure/util/sha256.cpp
)

# ==================================================
# Includes
# ==================================================

target_include_directories(acme_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${LIBPQ_INCLUDE_DIR}
)

# ==================================================
# Compiler Warnings
# ==================================================

if(MSVC)
    target_compile_options(acme_core PRIVATE
        /W4
    )
else()
    target_compile_options(acme_core PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# ==================================================
# Link Libraries
# ==================================================

target_link_libraries(acme_core
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ${LIBPQ_LIBRARY}
)

# ==================================================
# Main Executable
# ==================================================

add_executable(acme_server_demo
    src/main.cpp
)

target_link_libraries(acme_server_demo
    PRIVATE
        acme_core
)

# ==================================================
# Test Executable
# ==================================================

add_executable(test_acme_server
    tests/test_main.cpp
)

target_link_libraries(test_acme_server
    PRIVATE
        acme_core
)

# ==================================================
# Testing
# ==================================================

enable_testing()

add_test(
    NAME acme_tests
    COMMAND $<TARGET_FILE:test_acme_server>
)

# ==================================================
# Status
# ==================================================

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "libpq include: ${LIBPQ_INCLUDE_DIR}")
