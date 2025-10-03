MIT License

Copyright (c) 2024 Threat Hunting SQL Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# Threat Hunting SQL Repository

## Overview
This repository provides threat hunting SQL queries that security operations center (SOC) analysts and threat hunters can run directly against PostgreSQL-backed log stores. Each query focuses on a common detection scenario and is heavily documented so you can adapt it to your environment quickly.

## Repository layout
- `login-anomalies/` — detections for failed logins and new-location logins.
- `data-access-patterns/` — baselining and anomaly detection for data access activity.
- `privilege-escalation/` — monitoring for changes to user permissions.
- `examples/` — sample data setup and helper script to run the queries.

## Getting started
1. **Prepare PostgreSQL:** Ensure you have access to a PostgreSQL 13+ instance. Create a database and a user with privileges to create tables and run the detections.
2. **Load sample data:**
   ```bash
   psql -h <HOST> -U <USER> -d <DATABASE> -f examples/sample-data-setup.sql
   ```
3. **Run detections:** Use the provided script or run the SQL files individually:
   ```bash
   bash examples/run-queries.sh
   ```
   The script contains placeholder connection details (`<HOST>`, `<USER>`, `<DATABASE>`, `<PASSWORD>`). Edit them at the top of the script before running, or export matching environment variables.

## Running SQL manually
To execute a single detection:
```bash
psql -h <HOST> -U <USER> -d <DATABASE> -v threshold:=5 -f login-anomalies/failed-login-detection.sql
```
Replace the placeholder values with your PostgreSQL connection parameters. SQL variables can be overridden via the `-v` flag when using `psql`.

## Tuning thresholds and next steps
- Each SQL file exposes parameters (window sizes, thresholds, multipliers) through well-commented CTEs. Modify them directly or override with `psql -v` as needed.
- Review false-positive guidance in each query. Consider whitelisting known services, VPN gateways, and expected maintenance activity.
- Extend the detections with additional logic such as user context enrichment or mapping to alert severity.
- Convert the SQL to SIEM rules by mapping output columns to alert fields (e.g., severity, user identifier, source IP) and integrating with your alerting workflow.

## Contributing & roadmap
Future enhancements could include additional detectors (e.g., MFA anomalies, lateral movement patterns) and automation scripts to convert these queries into scheduled jobs or SIEM-compatible formats.

Feel free to fork, adapt, and contribute improvements or new detections.
