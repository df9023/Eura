#!/bin/bash
# Test script for API endpoints

BASE_URL="http://localhost:8000"

echo "Testing Root Endpoint (GET /)..."
curl -s "$BASE_URL/" | jq .
echo -e "\n"

echo "Testing Health Endpoint (GET /health)..."
curl -s "$BASE_URL/health" | jq .
echo -e "\n"

echo "Testing Scan Repo Endpoint (POST /scan-repo)..."
echo "Note: This requires valid GitHub credentials and will fail without them"
curl -X POST "$BASE_URL/scan-repo" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_name": "owner/repo",
    "installation_id": 12345
  }' | jq .
echo -e "\n"

echo "Testing OPTIONS (CORS preflight)..."
curl -X OPTIONS "$BASE_URL/scan-repo" \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -v
echo -e "\n"

