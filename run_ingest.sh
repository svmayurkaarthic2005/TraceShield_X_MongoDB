#!/bin/bash
cd /mnt/c/TraceShield-X-main/TraceShield-X-main
./ingestion/venv/bin/python -m uvicorn ingestion.main:app --host 0.0.0.0 --port 8001
