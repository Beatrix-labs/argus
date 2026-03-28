# 📄 PRD: Argus v0.5.0 - Active IPS & Native Firewall Integration

**Project Name**: Argus (Security Intelligence Engine)

**Version**: 0.5.0

**Developer**: Beatrix-labs

## 1. Executive Summary

Transforms Argus from just a passive detection system (IDS) into an active defense system (IPS) capable of disconnecting threats in real-time at the Linux kernel level using iptables or nftables.

## 2. Target Environment

- **Primary**: Linux Cloud Servers (Ubuntu, Debian, Alpine).
- **Secondary**: Android/Termux
- **Architecture**: Optimized for ARM64 and x86_64.

## 3. Core Features

### 3.1 Native Firewall Driver

- **Action**: Mengeksekusi perintah shell iptables -A INPUT -s [IP] -j DROP.
- **Fallback**: Jika iptables tidak tersedia, coba gunakan nftables.
- **Permission Check**: Harus melakukan pengecekan akses root atau sudo saat inisialisasi.

### 3.2 Advanced Scoring System

- **Threshold**: IP akan diblokir hanya jika mencapai skor ambang batas (default: 10 poin).
- **Weighting**:
  - SQLi/XSS Detection: 5 Poin.
  - Brute Force Attempt: 2 Poin.
  - Path Traversal: 4 Poin.
- ** Window**: Skor dihitung dalam rentang waktu 60 detik (Rolling Window).

### 3.3 Dynamic TTL (Time-To-Live) & Auto-Unban

- **Level 1**: Pelanggaran pertama = Banned selama 1 Jam.
- **Level 2**: Pelanggaran berulang = Banned selama 24 Jam.
- **Cleaner**: Background Goroutine yang mengecek tabel firewall setiap 5 menit untuk menghapus IP yang masa banned-nya sudah habis.

### 3.4 Dry-Run Mode

- Flag --dry-run untuk mensimulasikan pemblokiran di log tanpa benar-benar mengubah aturan firewall (Sangat penting untuk fase testing).

## 4. Technical Architecture

### 4.1 Non-Blocking Concurrency

- **Problem**: Perintah shell iptables butuh waktu (~20-50ms). Jika ribuan IP diblokir sekaligus, sistem bisa hang.
- **Solution**: Gunakan Buffered Go Channels sebagai antrian (Queue).
  - Worker Pool deteksi mengirim IP ke channel.
  - Satu dedicated worker (Remediation Worker) mengambil dari channel dan mengeksekusi perintah satu per satu secara sekuensial agar tabel kernel tetap stabil.

### 4.2 Performance Metrics

- **Throughput**: Tidak boleh menurunkan performa scanner di bawah 8,000 lines/sec.
- **Memory**: Overhead RAM tambahan maksimal 15MB untuk menyimpan state skor IP.

## 5. Success Metrics

1. Accuracy: 100% IP yang terdaftar di banned_ips.txt juga harus muncul di output iptables -L.
2. Stability: Tidak terjadi race condition atau deadlock saat memproses serangan volumetrik (Flood).
3. Resiliency: Sistem tetap berjalan meskipun perintah firewall gagal.

6. User Interface (CLI Output)

[ALERT] [SQLi] [192.168.1.50] - Score: 10/10 - ACTION: BANNED (1h)
[SYSTEM] Executing: sudo iptables -A INPUT -s 192.168.1.50 -j DROP

