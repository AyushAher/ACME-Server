cmake_minimum_required(VERSION 3.16)

project(acme_server_demo VERSION 1.0 LANGUAGES CXX)

# ==================================================
# C++ Configuration
# ==================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ==================================================
# Dependencies
# ==================================================

# OpenSSL
find_package(OpenSSL REQUIRED)
find_package(PostgreSQL REQUIRED)

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

# if(NOT LIBPQ_INCLUDE_DIR)
#     message(FATAL_ERROR "PostgreSQL headers (libpq-fe.h) not found")
# endif()

# if(NOT LIBPQ_LIBRARY)
#     message(FATAL_ERROR "PostgreSQL library (libpq.lib) not found")
# endif()

# message(STATUS "PostgreSQL Include: ${LIBPQ_INCLUDE_DIR}")
# message(STATUS "PostgreSQL Library: ${LIBPQ_LIBRARY}")

# ==================================================
# Core Library
# ==================================================

add_library(acme_core

    # ---------- application ----------
    src/application/acme_workflow_service.cpp
    src/application/acme_account_service.cpp
    src/application/certificate_order_service.cpp
    src/application/eab_service.cpp
    src/application/nonce_service.cpp

    # ---------- infrastructure ----------
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

    # PostgreSQL
    src/infrastructure/postgres_client.cpp
    src/infrastructure/postgres_repositories.cpp
    src/infrastructure/postgres_serialization.cpp

    src/infrastructure/shell_http_client.cpp
    src/infrastructure/transport/acme_http_server.cpp

    # ---------- utilities ----------
    src/infrastructure/util/acme_protocol.cpp
    src/infrastructure/util/base64url.cpp
    src/infrastructure/util/command_runner.cpp
    src/infrastructure/util/file_store.cpp
    src/infrastructure/util/json.cpp
    src/infrastructure/util/hmac_sha256.cpp
    src/infrastructure/util/random.cpp
    src/infrastructure/util/sha256.cpp
)

# ==================================================
# Includes
# ==================================================

target_include_directories(acme_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${LIBPQ_INCLUDE_DIR}
        ${PostgreSQL_INCLUDE_DIRS}

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
        PostgreSQL::PostgreSQL

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
    COMMAND test_acme_server
)

# ==================================================
# Status
# ==================================================

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")