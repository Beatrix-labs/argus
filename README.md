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

Ensure you have Go installed (1.20+ recommended). 

Clone the repository and build the binary:

```bash
git clone https://github.com/Beatrix-labs/argus.git
cd argus
go build -o argus cmd/argus/main.go
```

## Usage

Argus can read from a static log file or process real-time streams via standard input (stdin).

**Analyze a static file:**

```bash
./argus -file /var/log/nginx/access.log
```

**Analyze a real-time stream (Piping):**

```bash
tail -f /var/log/nginx/access.log | ./argus
```

## Configuration

Threat signatures and behavioral thresholds can currently be modified within the `internal/engine` package.

- `detector.go`: Contains the regex patterns and native checks.
- `behavior.go`: Contains the thresholds (e.g., 5 errors per minute) for the stateful tracker.

## License

MIT © Betarix-labs
Original Creator - [soft-meo](https://github.com/soft-meo)
