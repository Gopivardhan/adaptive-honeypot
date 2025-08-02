# Adaptive Honeypot System for Dynamic Threat Profiling

This project implements a multi‑service honeypot designed to profile malicious
scanning behaviour without exposing any real systems to compromise. It
simulates common services (HTTP, SSH and FTP/SMB) while logging all
interactions, detecting attacker fingerprints and visualising the results in a
web dashboard.

## Features

* **Multi‑service simulation** — HTTP server with fake CMS endpoints and
  decoy vulnerabilities, a fake SSH login prompt and an FTP/SMB service that
  invites credentials but never authenticates them.
* **Fingerprint detection** — simple heuristics identify common tools such as
  `sqlmap`, `nikto`, `nmap` and brute force scripts based on headers,
  request patterns and payloads.
* **Adaptive responses** — HTTP responses randomise `Server` and
  `X‑Powered‑By` headers to frustrate fingerprinting and inject decoy
  vulnerabilities tailored to the detected scanning tool.
* **Extensive logging** — each interaction is stored both in memory and in
  a SQLite database (`logs/honeypot.db`) with fields for timestamp, service,
  request type, path, payload, detected tool, classification and metadata.
* **Dashboard** — a Dash web application (`dashboard/app.py`) displays
  attack counts over time, tool usage frequency and a table of recent events.
* **Pluggable design** — services share a central logger; additional services
  can be added easily.

## Directory Structure

```
adaptive_honeypot/
├── honeypot_core/
│   ├── manager.py        # orchestrates the honeypot services
│   ├── logger.py         # unified event logger backed by SQLite
│   ├── http_honeypot.py  # web service with fake vulnerabilities
│   ├── ssh_honeypot.py   # fake SSH login prompt
│   ├── ftp_honeypot.py   # fake FTP/SMB service
├── detectors/
│   └── fingerprint.py    # tool fingerprinting and client classification
├── dashboard/
│   └── app.py            # Dash application for visualising events
├── logs/                 # database and exported logs
├── requirements.txt      # Python dependencies
└── README.md             # this file
```

## Quick Start

The honeypot requires Python 3.8+ and the dependencies listed in
`requirements.txt`. We recommend isolating these into a virtual environment.

### 1. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Run the honeypot services

The following command launches the HTTP (port 8080), SSH (port 2222) and FTP
(port 2121) honeypots simultaneously:

```bash
python -m honeypot_core.manager
```

You can customise the ports and database path by calling the `run_all` function
from your own script:

```python
from honeypot_core.manager import run_all
run_all(http_port=8000, ssh_port=2200, ftp_port=2100, db_path="logs/custom.db")
```

### 3. Generate traffic

Point your browser or terminal tools at the honeypot ports. For example:

```bash
# HTTP
curl http://localhost:8080/
curl http://localhost:8080/wp-admin

# SSH
nc localhost 2222

# FTP
nc localhost 2121
```

Credentials entered in the fake SSH and FTP services will be logged but never
used for any authentication.

### 4. Visualise attacks with the dashboard

While the honeypot is running, start the dashboard in a separate terminal:

```bash
python dashboard/app.py --db logs/honeypot.db --port 8050
```

Open [http://localhost:8050](http://localhost:8050) in your browser to view
interactive graphs of attack frequency, tool usage and recent events.

## Detection Heuristics

The detection logic in `detectors/fingerprint.py` uses simple rule‑based
heuristics:

* **Tool detection** — certain substrings in the `User-Agent` header or request
  path map to known scanners (`sqlmap`, `nikto`, `nmap`, etc.). SQL injection
  keywords in POST bodies also trigger the `sql_injection` tool.
* **Client classification** — if a known tool is detected the client is
  classified as a scanner. Otherwise, a burst of more than five requests in
  under two seconds is labelled as a bot; all other traffic is treated as
  human.

You can extend these heuristics or plug in a machine learning classifier by
modifying `detect_tool` and `classify_client`.

## Notes

* **Safety** — none of the services implement any real functionality. They
  never execute commands or expose files on the host. All responses are
  synthetic and should not introduce vulnerabilities into the host system.
* **GeoIP** — the dashboard contains a placeholder for geographic lookups via
  the `geoip2` library. To enable country mapping you must download a free
  GeoLite2 database from MaxMind and point `geoip2.database.Reader` at the
  `.mmdb` file. Without this database, the country code will default to
  `Unknown`.
* **Testing** — the system has been tested locally using `curl`, `nc` and
  synthetic traffic generators. You should exercise caution when exposing
  these ports on a public network; consider using firewalls or network
  namespaces to restrict inbound connections during evaluation.

## License

This project is released under the MIT License. See `LICENSE` for details.
