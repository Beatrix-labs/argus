# Argus v0.5.0 (Active IPS & Native Firewall Integration)

Argus is a high-performance, concurrent, and stateful Intrusion Detection and Prevention System (IDS/IPS) engineered in Go. Designed to monitor web server access logs in real-time, Argus accurately detects known attack signatures and anomalous behavioral patterns with extremely low memory and CPU footprint.

Developed as a core component of the Beatrix-labs security ecosystem, Argus operates as an active defense layer, capable of disconnecting threats in real-time at the Linux kernel level.

## Core Capabilities (v0.5.0)

### 🛡️ Active IPS (Bouncer)
* **Native Firewall Driver**: Automatically executes `iptables` (IPv4) or `ip6tables` (IPv6) commands to drop malicious traffic.
* **Smart De-duplication**: Intelligent rule checking (`-C`) ensures the kernel firewall table remains clean without duplicate entries.
* **Multi-Backend Support**: Full support for both `iptables/ip6tables` and modern `nftables`.
* **Dynamic TTL (Auto-Unban)**: Features a two-level ban system:
    * **Level 1**: Initial offense = 1-hour ban.
    * **Level 2**: Repeat offender = 24-hour ban.
* **Background Cleaner**: A dedicated goroutine periodically clears expired bans from the kernel firewall table.
* **Non-Blocking Remediation**: Utilizes a buffered queue (Go Channels) for firewall actions to ensure log processing throughput remains unaffected (~8,000+ lines/sec).

### 📈 Advanced Scoring System
* **Persistent Scoring**: Threat scores are now persisted to disk, ensuring continuity across service restarts.
* **Weighted Detection**: Not all attacks are equal. Argus assigns scores based on threat type:
    * **SQLi/XSS**: 5 Points.
    * **Path Traversal**: 4 Points.
    * **Brute Force/Fuzzing**: 2 Points.
* **IP Whitelisting**: Built-in support for whitelisting trusted IPs (Search bots, internal monitoring) to prevent accidental bans.
* **Intelligent Thresholds**: IPs are only blocked once they cross a configurable threshold (default: 10 points) within a 60-second rolling window.

### 🔍 Threat Detection Engine
* **Parallel Processing Pipeline**: High-performance worker pool utilizing Go routines for massive throughput.
* **Native File Tailing**: Built-in log tailing mechanism for continuous real-time monitoring without external pipes.
* **Flexible Log Parsing**: Supports custom regex patterns to accommodate various log formats beyond the standard Nginx/Apache Combined.
* **Zero-ReDoS HPP Detection**: Uses native URL parsing logic to detect HTTP Parameter Pollution safely.
* **Lazy URL Decoding**: Optimized CPU usage by decoding only when necessary.
* **State Persistence**: Intelligently loads and saves the active ban list across service restarts.

## Installation

### Building from Source
Requires Go v1.20+

```bash
git clone https://github.com/Beatrix-labs/argus.git
cd argus
go build -ldflags="-s -w" -o argus cmd/argus/main.go
```

### Deployment via Docker

```bash
docker build -t beatrix/argus:v0.5.0 .

# Running with host network or CAP_NET_ADMIN might be needed for iptables
docker run -d \
  --name argus-ips \
  --cap-add=NET_ADMIN \
  -v /var/log/nginx:/logs \
  -v $(pwd)/rules:/app/rules \
  -v $(pwd)/configs:/app/configs \
  beatrix/argus:v0.5.0 \
  -file /logs/access.log -rules /app/rules
```

## Usage

### Command Line Flags

- `-file`: Path to the log file (stdin if empty).
- `-tail`: Continuously monitor the log file (requires `-file`).
- `-rules`: Directory containing JSON signatures (default: `rules`).
- `-json`: Output path for SIEM JSON alerts (default: `argus_alerts.json`).
- `-workers`: Number of parallel workers (default: CPU count).
- `-dry-run`: Simulate blocking without modifying firewall rules (Recommended for testing).

### Real-time Monitoring

```bash
# Using native tailing
./argus -file /var/log/nginx/access.log -tail -rules ./rules -dry-run
```

## Configuration (`configs/argus.yml`)

```yaml
log_source:
  path: "/var/log/nginx/access.log"
  custom_log_regex: "" # Optional custom regex for non-standard logs

engine:
  behavioral:
    error_threshold: 5
    window_seconds: 60
  scoring:
    threshold: 10
    window_seconds: 60
    weight_sqli: 5
    weight_brute: 2
    weight_path_trav: 4
    score_file: "scores.json"
    whitelist:
      - "127.0.0.1"
      - "::1"

action:
  ban_file: "banned_ips.txt"
  ttl_level_1: 60      # minutes
  ttl_level_2: 1440    # minutes (24h)
  use_iptables: true   # uses ip6tables automatically for IPv6
  dry_run: false
```

## License

MIT © Beatrix-labs
Original Creator - [soft-meo](https://github.com/soft-meo)
