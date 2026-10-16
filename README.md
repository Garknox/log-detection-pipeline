# Automated Log Ingestion & Threat Detection Pipeline

A modular Python-based Security Operations Center (SOC) detection pipeline designed to ingest web access logs, parse structured event fields, and detect malicious attack signatures (SQL Injection, Path Traversal, Brute Force) in real-time.

## Architecture
1. **Ingestion & Parsing**: RegEx-based extraction of raw log formats into structured event payloads.
2. **Detection Engine**: Signature matching against customizable security rules.
3. **Threat Intel Enrichment**: IP reputation lookups via external APIs.
4. **Alerting**: Webhook integration for real-time notifications.

## Environment & Setup
- **OS**: Ubuntu 24.04 LTS
- **Language**: Python 3.12+
- **Environment**: Managed via Python `venv`
