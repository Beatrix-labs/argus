# Argus

Argus is a high-performance, concurrent, and stateful Intrusion Detection and Prevention System (IDS/IPS) engineered in Go. It is designed to monitor web server logs in real-time, detecting both known attack signatures and anomalous behavioral patterns with minimal resource consumption.

Developed as a core component of the Beatrix-labs security ecosystem.

## Core Features

* **Stateful Behavioral Analysis**: Tracks IP behavior over time to detect directory fuzzing, enumeration, and brute-force attacks.
* **Signature-Based Detection**: Identifies OWASP Top 10 threats including Cross-Site Scripting (XSS), SQL Injection (SQLi), and Local File Inclusion (LFI).
* **Zero-ReDoS HPP Detection**: Utilizes Go's native URL parsing to detect HTTP Parameter Pollution, eliminating the risk of Regular Expression Denial of Service (ReDoS).
* **High-Throughput Parsing**: Employs zero-allocation extraction techniques and compiled regular expressions to process massive log files without memory leaks.
* **Out-of-Band Architecture**: Analyzes traffic passively via log streams, ensuring zero added latency to the production web application.
* **Active Remediation (IPS)**: Includes a Bouncer module capable of blacklisting malicious IPs automatically upon detection.

## Architecture

Argus operates by reading standard access logs (e.g., Nginx, Apache). The pipeline consists of:
1.  **Scanner**: Reads logs line-by-line using buffered I/O.
2.  **Parser**: Extracts the IP, HTTP Method, Path, Status Code, and User-Agent.
3.  **Signature Engine**: Decodes URLs and evaluates the path against predefined threat matrices.
4.  **Behavioral Engine**: Maintains an in-memory, thread-safe state of client error rates (4xx/5xx).
5.  **Action / Bouncer**: Dispatches alerts and executes IP bans.

## Installation

Ensure you have Go installed (v1.26.1+ recommended for optimal performance).

### Building from Source
Clone the repository and compile the highly-optimized binary:

```bash
git clone https://github.com/Beatrix-labs/argus.git
cd argus
go build -ldflags="-s -w" -o argus cmd/argus/main.go
```

### Deployment via Docker

For production environments, use the provided multi-stage Dockerfile:

```bash
docker build -t beatrix/argus:v0.1.0 .
docker run -v /var/log/nginx:/logs beatrix/argus:v0.1.0 -file /logs/access.log
```

## Usage

Argus is designed for flexibility, supporting both static analysis and real-time log tailing.

### 1. Direct Execution

Analyze a specific log file locally:

```bash
./argus -file testdata/access.log
```

### 2. Pipeline (Real-time Monitoring)

Pipe your live web server logs directly into Argus for instant threat detection:

```bash
tail -f /var/log/nginx/access.log | ./argus
```

### 3. Background Service (Systemd)

In a real server setup, you can run Argus as a system service to ensure 24/7 monitoring.

```bash
nohup ./argus -file /var/log/nginx/access.log >> argus.log 2>&1 &
```

## Configuration

Threat signatures and behavioral thresholds can currently be modified within the `internal/engine` package.

- `detector.go`: Contains the regex patterns and native checks.
- `behavior.go`: Contains the thresholds (e.g., 5 errors per minute) for the stateful tracker.

## License

MIT © Betarix-labs
Original Creator - [soft-meo](https://github.com/soft-meo)
