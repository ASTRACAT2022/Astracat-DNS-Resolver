#!/bin/bash

# Set the DNS server and port
DNS_SERVER="localhost"
DNS_PORT="5454"

# Define arrays of domains and record types to test
domains=("example.com" "ipv6.google.com" "www.example.com" "gmail.com" "example.com")
record_types=("A" "AAAA" "CNAME" "MX" "TXT")

# Function to test a DNS query
test_dns_query() {
  domain="$1"
  record_type="$2"

  echo "Testing ${domain} ${record_type} record..."

  # Measure the time taken for the first query
  start=$(date +%s.%N)
  dig @${DNS_SERVER} -p ${DNS_PORT} ${domain} ${record_type} +short
  result=$?
  end=$(date +%s.%N)
  duration=$(echo "$end - $start" | bc)

  if [ $result -eq 0 ]; then
    echo "  ${domain} ${record_type} - First query: OK (Time: ${duration} seconds)"
  else
    echo "  ${domain} ${record_type} - First query: FAILED"
  fi

  # Measure the time taken for the second query (to test caching)
  start=$(date +%s.%N)
  dig @${DNS_SERVER} -p ${DNS_PORT} ${domain} ${record_type} +short
  result=$?
  end=$(date +%s.%N)
  duration=$(echo "$end - $start" | bc)

  if [ $result -eq 0 ]; then
    echo "  ${domain} ${record_type} - Second query: OK (Time: ${duration} seconds)"
  else
    echo "  ${domain} ${record_type} - Second query: FAILED"
  fi

  echo ""
}

# Loop through the domains and record types
for i in $(seq 0 $((${#domains[@]} - 1))); do
  domain="${domains[$i]}"
  record_type="${record_types[$i]}"
  test_dns_query "${domain}" "${record_type}"
done

echo "Testing complete."
