# Argus

Argus is a high-performance, concurrent, and stateful Intrusion Detection and Prevention System (IDS/IPS) engineered in Go. Designed to monitor web server access logs in real-time, Argus accurately detects known attack signatures and anomalous behavioral patterns with extremely low memory and CPU footprint.

Developed as a core component of the Beatrix-labs security ecosystem, Argus operates out-of-band, ensuring zero added latency to your production web applications.

## Core Capabilities

### Threat Detection Engine
* **Dynamic Rule Engine**: Supports hot-reloadable threat signatures via JSON files. Deploy zero-day mitigation rules instantly without recompiling the binary.
* **Multi-Target Analysis**: Signature rules can be specifically mapped to scan either the HTTP `PATH` or the `USER_AGENT` header.
* **Zero-ReDoS HPP Detection**: Utilizes Go's native URL parsing logic to detect HTTP Parameter Pollution, completely eliminating the risk of Regular Expression Denial of Service (ReDoS).
* **Stateful Behavioral Analysis**: Tracks IP behavior across configurable time windows to detect directory fuzzing, enumeration, and brute-force attempts.

### Remediation & Enterprise Integration
* **Automated IPS (Bouncer)**: Safely blacklists malicious IPs in real-time. Utilizes an O(1) in-memory cache and `sync.RWMutex` to prevent disk I/O bottlenecks during volumetric attacks.
* **State Persistence**: The IPS module intelligently loads historical blacklist data upon startup to maintain continuous security state across service restarts.
* **SIEM Integration Ready**: Features a high-throughput, thread-safe JSON stream encoder for detected threats, enabling seamless ingestion by enterprise log aggregators (e.g., Elasticsearch, Splunk).

### Architecture & Safety
* **High-Throughput Parsing**: Employs zero-allocation extraction techniques and compiled regular expressions to process massive log files continuously.
* **Memory Leak Prevention**: Features a background garbage-collection routine (Sweeper) that periodically clears inactive IP states from RAM.
* **Large Payload Protection**: Implements a customized 1MB buffer scanner to safely process massive, obfuscated URLs without causing runtime panics.
* **Centralized YAML Configuration**: Separates environmental configuration from the core binary using standardized YAML formats.

## System Pipeline

Argus analyzes standard access logs (e.g., Nginx, Apache) through a highly optimized pipeline:
1. **Ingestion**: Reads logs line-by-line using customized buffered I/O.
2. **Extraction**: Parses essential metadata (IP, Method, Path, Status Code, User-Agent).
3. **Signature Phase**: Evaluates payloads against dynamic JSON threat matrices and native application logic.
4. **Behavioral Phase**: Maintains an in-memory, thread-safe state of client error rates (4xx/5xx).
5. **Action Phase**: Dispatches structured JSON alerts and executes automatic IP bans.

## Installation

Argus requires Go v1.20 or higher.

### Building from Source

Clone the repository and compile the optimized binary:

```bash
git clone [https://github.com/Beatrix-labs/argus.git](https://github.com/Beatrix-labs/argus.git)
cd argus
go build -ldflags="-s -w" -o argus cmd/argus/main.go
```

### Deployment via Docker

For production environments, utilize the provided multi-stage Docker setup. Map the necessary volumes for logs, configurations, and rules.

```bash
docker build -t beatrix/argus:v0.2.0 .

docker run -d \
  --name argus-ips \
  -v /var/log/nginx:/logs \
  -v $(pwd)/rules:/app/rules \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/reports:/app/reports \
  beatrix/argus:v0.2.0 \
  -file /logs/access.log -rules /app/rules -json /app/reports/alerts.json
```

## Usage

Argus provides a flexible CLI, supporting both static log analysis and real-time log tailing.

### Command Line Flags

- `-file`: Path to the web server access log. Leave empty to read from `stdin`.
- `-rules`: Directory containing the JSON signature rules (default: `rules`).
- `-json`: Output path for the SIEM-compatible JSON alerts (default: `argus_alerts.json`).

### Real-time Monitoring (Pipeline)

Pipe your live web server logs directly into Argus for instant threat detection and remediation:

```bash
tail -f /var/log/nginx/access.log | ./argus -rules ./rules -json ./alerts.json
```

### Static Analysis

Analyze historical log data rapidly:

```bash
./argus -file testdata/access.log -rules ./rules -json alerts.json
```

## Configuration

Argus enforces a strict separation between core application settings and threat intelligence.

### 1. Global Configuration (`configs/argus.yml`)

Define system behavior, tracking thresholds, and output paths:

```yaml
engine:
  behavioral:
    error_threshold: 5
    window_seconds: 60
action:
  ban_file: "banned_ips.txt"
```

### 2. Threat Signatures (`rules/*.json`)

Manage threat signatures by adding JSON files to the `rules/` directory. Argus compiles these dynamically upon initialization.

```json
[
  {
    "name": "Local_File_Inclusion",
    "description": "Detects Path Traversal / Directory climbing attempts",
    "severity": "Critical",
    "pattern": "(?i)(\\.\\./\\.\\./|\\.\\.%2F|/etc/passwd|/windows/win\\.ini|cmd\\.exe)",
    "target": "PATH"
  }
]
```

## License

MIT © Beatrix-labs
Original Creator - [soft-meo](https://github.com/soft-meo)
