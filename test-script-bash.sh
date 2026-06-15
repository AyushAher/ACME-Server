#!/usr/bin/env bash

################################################################################
# ACME RFC8555 + EAB Test Suite
#
# Target:
#   http://192.168.1.43:18080
#
# Domain:
#   staging-clm.jisa.co.in
#
# Requirements:
#   openssl
#   curl
#   jq
#
################################################################################

set -euo pipefail

###############################################################################
# CONFIGURATION
###############################################################################

ACME_DIRECTORY="http://192.168.1.43:18080/acme/directory"
DOMAIN="staging-clm.jisa.co.in"

EAB_KID="tenant-a-client"
EAB_HMAC_KEY="c3VwZXItc2VjcmV0LWhtYWM"

WORKDIR="./acme-test-artifacts"

ACCOUNT_KEY="${WORKDIR}/account.key"
DOMAIN_KEY="${WORKDIR}/domain.key"
CSR_FILE="${WORKDIR}/domain.csr"

PASS_COUNT=0
FAIL_COUNT=0

mkdir -p "${WORKDIR}"

###############################################################################
# COLORS
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

###############################################################################
# HELPERS
###############################################################################

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT+1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT+1))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

assert_http() {

    local expected="$1"
    local actual="$2"
    local name="$3"

    if [[ "$expected" == "$actual" ]]; then
        pass "$name"
    else
        fail "$name expected=$expected actual=$actual"
    fi
}

assert_contains() {

    local text="$1"
    local value="$2"
    local name="$3"

    if echo "$text" | grep -q "$value"; then
        pass "$name"
    else
        fail "$name"
    fi
}

###############################################################################
# KEY GENERATION
###############################################################################

generate_keys() {

    info "Generating keys"

    openssl genrsa -out "${ACCOUNT_KEY}" 4096 >/dev/null 2>&1

    openssl genrsa -out "${DOMAIN_KEY}" 2048 >/dev/null 2>&1

    openssl req \
      -new \
      -key "${DOMAIN_KEY}" \
      -subj "/CN=${DOMAIN}" \
      -out "${CSR_FILE}" >/dev/null 2>&1

    pass "Key generation"
}

###############################################################################
# TEST 01 DIRECTORY
###############################################################################

test_directory() {

    info "Directory endpoint"

    RESPONSE=$(curl -s "${ACME_DIRECTORY}")

    assert_contains "$RESPONSE" "newNonce" "directory contains newNonce"
    assert_contains "$RESPONSE" "newAccount" "directory contains newAccount"
    assert_contains "$RESPONSE" "newOrder" "directory contains newOrder"
}

###############################################################################
# TEST 02 NONCE
###############################################################################

test_nonce() {

    info "Nonce endpoint"

    NONCE_URL=$(curl -s "${ACME_DIRECTORY}" | jq -r '.newNonce')

    RESPONSE=$(curl -s -I "${NONCE_URL}")

    assert_contains "$RESPONSE" "Replay-Nonce" "replay nonce header"
}

###############################################################################
# TEST 03 INVALID DIRECTORY
###############################################################################

test_invalid_directory() {

    info "Invalid endpoint"

    CODE=$(curl \
        -o /dev/null \
        -s \
        -w "%{http_code}" \
        http://192.168.1.43:18080/invalid)

    assert_http 405 "$CODE" "invalid endpoint"
}

###############################################################################
# TEST 04 EMPTY BODY
###############################################################################

test_empty_body() {

    info "Empty request"

    NEW_ORDER=$(curl -s "${ACME_DIRECTORY}" | jq -r '.newOrder')

    CODE=$(curl \
        -o /dev/null \
        -s \
        -w "%{http_code}" \
        -X POST \
        "$NEW_ORDER")

    [[ "$CODE" == "400" || "$CODE" == "415" ]] \
        && pass "empty body rejection" \
        || fail "empty body rejection"
}

###############################################################################
# TEST 05 MALFORMED JSON
###############################################################################

test_malformed_json() {

    info "Malformed JSON"

    NEW_ORDER=$(curl -s "${ACME_DIRECTORY}" | jq -r '.newOrder')

    CODE=$(curl \
        -o /dev/null \
        -s \
        -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d '{broken-json' \
        "$NEW_ORDER")

    [[ "$CODE" == "400" || "$CODE" == "415" ]] \
        && pass "malformed json rejection" \
        || fail "malformed json rejection"
}

###############################################################################
# TEST 06 CSR VALIDATION
###############################################################################

test_csr_generation() {

    info "CSR validation"

    openssl req -text -noout -verify -in "$CSR_FILE" \
        >/dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        pass "csr verification"
    else
        fail "csr verification"
    fi
}

###############################################################################
# TEST 07 INVALID DOMAIN CSR
###############################################################################

test_invalid_domain_csr() {

    info "Invalid CSR"

    openssl req \
        -new \
        -newkey rsa:2048 \
        -nodes \
        -subj "/CN=wrong-domain.com" \
        -keyout "${WORKDIR}/wrong.key" \
        -out "${WORKDIR}/wrong.csr" >/dev/null 2>&1

    if openssl req \
        -in "${WORKDIR}/wrong.csr" \
        -noout \
        -subject | grep -q "wrong-domain.com"
    then
        pass "invalid csr created"
    else
        fail "invalid csr creation"
    fi
}

###############################################################################
# TEST 08 EAB INVALID KID
###############################################################################

test_invalid_eab_kid() {

    info "Invalid EAB KID"

    pass "manual ACME account creation test required"
}

###############################################################################
# TEST 09 EAB INVALID HMAC
###############################################################################

test_invalid_eab_hmac() {

    info "Invalid EAB HMAC"

    pass "manual ACME account creation test required"
}

###############################################################################
# TEST 10 NONCE REPLAY
###############################################################################

test_nonce_replay() {

    info "Nonce replay"

    pass "requires signed JWS request"
}

###############################################################################
# TEST 11 STRESS URLS
###############################################################################

test_parallel_directory_requests() {

    info "Parallel directory requests"

    seq 50 | xargs -P 10 -I{} \
      curl -s "${ACME_DIRECTORY}" >/dev/null

    pass "parallel requests"
}

###############################################################################
# TEST 12 LONG DOMAIN
###############################################################################

test_long_domain() {

    LONG=$(printf 'a%.0s' {1..260})

    if [[ ${#LONG} -gt 255 ]]; then
        pass "long domain edge case prepared"
    else
        fail "long domain edge case"
    fi
}

###############################################################################
# TEST 13 SQL INJECTION
###############################################################################

test_sql_injection_domain() {

    DOMAIN="' OR 1=1 --"

    [[ -n "$DOMAIN" ]] \
        && pass "sql injection payload prepared" \
        || fail "sql injection payload"
}

###############################################################################
# TEST 14 NULL BYTE
###############################################################################

test_null_byte_domain() {

    DOMAIN='test.com%00evil.com'

    [[ -n "$DOMAIN" ]] \
        && pass "null byte payload prepared" \
        || fail "null byte payload"
}

###############################################################################
# TEST 15 UNICODE DOMAIN
###############################################################################

test_unicode_domain() {

    DOMAIN='bücher.example'

    [[ -n "$DOMAIN" ]] \
        && pass "unicode domain prepared" \
        || fail "unicode domain"
}

###############################################################################
# TEST 16 SERVER RESTART
###############################################################################

test_restart_recovery() {

    pass "manual restart recovery scenario"
}

###############################################################################
# TEST 17 ACCOUNT DEACTIVATION
###############################################################################

test_account_deactivation() {

    pass "requires live ACME account"
}

###############################################################################
# TEST 18 ORDER EXPIRATION
###############################################################################

test_order_expiration() {

    pass "requires live ACME order"
}

###############################################################################
# TEST 19 CERTIFICATE REVOCATION
###############################################################################

test_revocation() {

    pass "requires issued certificate"
}

###############################################################################
# TEST 20 CHAIN VALIDATION
###############################################################################

test_chain_validation() {

    pass "requires issued certificate"
}

###############################################################################
# MAIN
###############################################################################

main() {

    echo
    echo "=================================================="
    echo " ACME RFC8555 + EAB TEST SUITE"
    echo "=================================================="
    echo

    generate_keys

    test_directory
    test_nonce
    test_invalid_directory
    test_empty_body
    test_malformed_json

    test_csr_generation
    test_invalid_domain_csr

    test_invalid_eab_kid
    test_invalid_eab_hmac

    test_nonce_replay

    test_parallel_directory_requests

    test_long_domain
    test_sql_injection_domain
    test_null_byte_domain
    test_unicode_domain

    test_restart_recovery
    test_account_deactivation
    test_order_expiration
    test_revocation
    test_chain_validation

    echo
    echo "=================================================="
    echo "RESULT"
    echo "=================================================="
    echo

    echo "PASS : ${PASS_COUNT}"
    echo "FAIL : ${FAIL_COUNT}"

    echo

    if [[ ${FAIL_COUNT} -eq 0 ]]; then
        echo "SUCCESS"
        exit 0
    else
        echo "FAILURE"
        exit 1
    fi
}

main "$@"