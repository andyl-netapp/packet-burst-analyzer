# packet-burst-analyzer

Analyze NFS / CIFS (SMB2) packet captures (`.pcap` / `.pcapng`) to detect **bursty workloads** and measure their impact on I/O latency.

The tool uses your locally installed **Wireshark / tshark** to extract protocol data, then produces a structured report and 4-panel chart showing:

- Request rate over time (burst windows highlighted in red)
- Latency over time (p50 / p95 per window)
- Latency CDF: burst vs. non-burst comparison
- Operation type breakdown (READ / WRITE / GETATTR / …)

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| Wireshark / tshark | any recent | Must be installed on your machine |
| pandas | ≥ 2.0 | |
| numpy | ≥ 1.24 | |
| matplotlib | ≥ 3.7 | |
| scipy | ≥ 1.11 | |

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/andyl-netapp/packet-burst-analyzer.git
cd packet-burst-analyzer

# 2. Install Python dependencies
pip install -r requirements.txt
```

> **Windows users:** tshark is usually at  
> `C:\Program Files\Wireshark\tshark.exe` after a standard Wireshark install.  
> The script finds it automatically; use `--tshark PATH` if it lives elsewhere.

---

## Quick Start

```bash
# Auto-detect NFS and SMB2, 10 ms windows (default)
python burst_analyzer.py capture.pcap

# NFS only, filter to READ and WRITE operations
python burst_analyzer.py capture.pcap --protocol nfs --ops READ WRITE

# See what operation types are present before diving in
python burst_analyzer.py capture.pcap --list-ops

# Restrict to a specific client IP
python burst_analyzer.py capture.pcap --client 192.168.1.10

# Tighter windows (5 ms) with a stricter burst threshold (3σ)
python burst_analyzer.py capture.pcap --window 5 --sigma 3

# Save chart to a folder and results to JSON
python burst_analyzer.py capture.pcap --output ./reports --json results.json

# Text report only (no chart generated)
python burst_analyzer.py capture.pcap --no-plot
```

---

## Command-Line Reference

| Argument | Default | Description |
|---|---|---|
| `pcap` | *(required)* | Path to `.pcap` or `.pcapng` capture file |
| `--protocol` | `auto` | `nfs` / `smb2` / `auto` (detect both) |
| `--window MS` | `10` | Time window size in milliseconds |
| `--sigma N` | `2.0` | Burst threshold = mean + N × σ |
| `--ops OP …` | all | Filter to specific ops, e.g. `READ WRITE` |
| `--client IP` | all | Only analyze traffic involving this IP |
| `--tshark PATH` | auto | Path to tshark binary |
| `--output DIR` | `.` | Directory for output charts |
| `--json FILE` | — | Save analysis results as JSON |
| `--no-plot` | — | Skip chart generation |
| `--list-ops` | — | List all operation types found, then exit |

---

## How It Works

### 1 — Data Extraction (tshark)

The script calls tshark with a protocol-specific display filter and extracts fields as TSV:

| Protocol | Display filter | Key latency field |
|---|---|---|
| NFS v3/v4 | `rpc.program == 100003` | `rpc.time` (on reply packets) |
| SMB2 | `smb2` | `smb2.time` (on response packets) |

Wireshark populates `rpc.time` / `smb2.time` automatically on reply/response packets — it represents the elapsed time from the matching request.  This avoids manual XID / MsgID matching.

### 2 — Operation Pairing & Latency

Only **reply / response packets** are used:

```
request_timestamp = reply_timestamp − rpc.time
latency_ms        = rpc.time × 1000
```

This produces one row per completed operation: `(timestamp, latency_ms, op_name)`.

### 3 — Burst Detection

The trace timeline is divided into fixed-size windows (default **10 ms**).  
Request counts per window are compared against a statistical threshold:

```
burst_threshold = mean(counts) + σ_multiplier × std(counts)
is_burst[w]     = counts[w] > burst_threshold
```

### 4 — Burstiness Metrics

| Metric | Formula | Threshold | Meaning |
|---|---|---|---|
| **CV** (Coefficient of Variation) | σ / μ | > 1 = bursty | Relative variability of request rate |
| **Fano Factor** | σ² / μ | > 2 = clustered | 1 = Poisson; higher = more bursty |
| **Peak-to-Mean Ratio** | peak / mean | intuitive | How many times the peak exceeds average |
| **Burst Ratio** | (peak − mean) / mean | intuitive | How far above average the peak is |

### 5 — Latency Comparison

Operations are split into two groups by window type.  
A **Mann-Whitney U test** (one-sided: burst > non-burst) provides statistical confirmation that burst windows cause elevated latency.

---

## Sample Output

```
══════════════════════════════════════════════════════════════════════
  NFS BURSTINESS ANALYSIS REPORT
══════════════════════════════════════════════════════════════════════

  SUMMARY  (suitable for customer / management presentation)
──────────────────────────────────────────────────────────────
  Capture duration :  60.0 s
  Total operations :  18,432

  Request rate per 10 ms window
    Average          :  3.1 ops  (307 ops/s)
    Typical busy     :  8 ops  (90th-percentile window)
    Peak             :  41 ops  — 13.2× the average

  Burst periods      :  47 out of 6000 windows (0.8% of the time)
  Burst threshold    :  > 12 ops/10 ms

  Latency during normal periods vs. burst periods
    p50  normal=    0.45 ms   burst=    1.82 ms      4.0× higher during bursts
    p95  normal=    2.10 ms   burst=   18.74 ms   ⚠  8.9× higher during bursts
    p99  normal=    4.30 ms   burst=   45.20 ms   ⚠ 10.5× higher during bursts

  Latency increase during bursts is statistically significant (p=3.2e-18).

  ⚠   CONCLUSION: Bursty workload is present and is causing higher latency.

  Top 5 busiest 10 ms windows (concrete burst examples)
      Time (s)     Ops   p95 lat (ms)
    ----------   -----   --------------
        12.340      41          45.20
        38.720      35          38.60
        ...
```

---

## License

MIT
