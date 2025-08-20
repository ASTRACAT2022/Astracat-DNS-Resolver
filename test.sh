#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

PORT=${1:-8053}
SERVER="127.0.0.1"

# Function to check if a record of a certain type exists
check_record() {
    local domain=$1
    local type=$2
    echo "Checking $type record for $domain..."
    output=$(dig @$SERVER -p $PORT $domain $type +short)
    if [[ -z "$output" ]]; then
        echo "FAIL: $type record for $domain not found."
        exit 1
    fi
    echo "PASS: $type record for $domain found."
}

# Function to check for CNAME
check_cname() {
    local domain=$1
    local target=$2
    echo "Checking CNAME for $domain..."
    # Get only the first line of output, as dig +short will return the full CNAME chain and A records
    output=$(dig @$SERVER -p $PORT $domain +short | head -n 1)
    if [[ "$output" != "$target" ]]; then
        echo "FAIL: CNAME for $domain should be $target, but got $output"
        exit 1
    fi
    echo "PASS: CNAME for $domain is correct."
}

# === Test Cases ===

# A record
check_record "example.com." "A"

# AAAA record
check_record "example.com." "AAAA"

# MX record
check_record "google.com." "MX"

# TXT record
check_record "example.com." "TXT"

# CNAME record
check_cname "www.example.com." "www.example.com-v4.edgesuite.net."

# Non-existent domain
echo "Checking non-existent domain..."
output=$(dig @$SERVER -p $PORT non-existent-domain-for-testing.com +short)
if [[ -n "$output" ]]; then
    echo "FAIL: Non-existent domain should not have a record, but got $output"
    exit 1
fi
echo "PASS: Non-existent domain handled correctly."


echo "All tests passed!"
