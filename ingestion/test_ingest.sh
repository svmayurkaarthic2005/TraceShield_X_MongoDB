#!/bin/bash
# test_ingest.sh — Simulate real-time ingestion events via curl

BASE="http://localhost:8001"

echo "=== Normal event (request_count=50) ==="
curl -s -X POST "$BASE/ingest" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.10","device":"laptop-01","request_count":50}' | python3 -m json.tool

echo ""
echo "=== Anomaly event (request_count=250) ==="
curl -s -X POST "$BASE/ingest" \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.99","device":"server-02","request_count":250}' | python3 -m json.tool

echo ""
echo "=== Anomaly with timestamp ==="
curl -s -X POST "$BASE/ingest" \
  -H "Content-Type: application/json" \
  -d '{"ip":"172.16.0.5","device":"router-03","request_count":500,"timestamp":"2026-04-10T02:30:00"}' | python3 -m json.tool

echo ""
echo "=== Health check ==="
curl -s "$BASE/health" | python3 -m json.tool
