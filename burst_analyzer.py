#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Packet Burst Analyzer — NFS / CIFS (SMB2) Burstiness Detection
===============================================================
Uses tshark to extract protocol data from a pcap file, then analyzes
request rates in configurable time windows to detect and quantify
bursty workloads and their impact on latency.

Usage:
  python burst_analyzer.py capture.pcap
  python burst_analyzer.py capture.pcap --protocol smb2
  python burst_analyzer.py capture.pcap --window 5 --sigma 3
  python burst_analyzer.py capture.pcap --ops READ WRITE --client 10.0.0.1
  python burst_analyzer.py capture.pcap --json results.json --no-plot
"""

import argparse
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend; works without a display
import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

# ──────────────────────────────────────────────────────────────────────────────
# Protocol definitions
# ──────────────────────────────────────────────────────────────────────────────

NFS3_OPS = {
    0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS",
    5: "READLINK", 6: "READ", 7: "WRITE", 8: "CREATE", 9: "MKDIR",
    10: "SYMLINK", 11: "MKNOD", 12: "REMOVE", 13: "RMDIR", 14: "RENAME",
    15: "LINK", 16: "READDIR", 17: "READDIRPLUS", 18: "FSSTAT",
    19: "FSINFO", 20: "PATHCONF", 21: "COMMIT",
}

NFS4_OPS = {
    # NFSv4 COMPOUND ops — map procedure number to name
    0: "NULL", 1: "COMPOUND",
}

SMB2_CMDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
    4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH",
    8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL",
    13: "ECHO", 14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY",
    16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK",
}

# tshark fields to extract for each protocol
TSHARK_NFS_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "rpc.msgtyp",        # 0 = call, 1 = reply
    "nfs.procedure_v3",
    "nfs.procedure_v4",
    "rpc.time",          # response time in seconds (populated on reply packets)
    "rpc.xid",
    "nfs.count3",        # NFSv3 byte count for READ/WRITE (present on both call and reply)
]

TSHARK_SMB2_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "smb2.flags.response",   # 0 = request, 1 = response
    "smb2.cmd",
    "smb2.time",             # response time in seconds (populated on response)
    "smb2.msg_id",
    "smb2.file_data_length", # bytes transferred in READ response
    "smb2.write_count",      # bytes confirmed in WRITE response
]

# ──────────────────────────────────────────────────────────────────────────────
# tshark helpers
# ──────────────────────────────────────────────────────────────────────────────

def find_tshark() -> str | None:
    """Return path to a working tshark binary, or None."""
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    # Also try locating tshark via Windows 'where' or Unix 'which'
    try:
        where_cmd = "where" if sys.platform == "win32" else "which"
        out = subprocess.run([where_cmd, "tshark"], capture_output=True,
                             text=True, timeout=5)
        for line in out.stdout.strip().splitlines():
            line = line.strip()
            if line and line not in candidates:
                candidates.append(line)
    except Exception:
        pass

    # Always try bare 'tshark' last (works if it's on PATH)
    if "tshark" not in candidates:
        candidates.append("tshark")

    for c in candidates:
        if c != "tshark" and not Path(c).exists():
            continue
        try:
            r = subprocess.run([c, "--version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return c
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None


def run_tshark(tshark: str, pcap: Path, display_filter: str, fields: list[str]) -> str:
    """Run tshark with the given filter and fields; return raw TSV output."""
    field_args: list[str] = []
    for f in fields:
        field_args += ["-e", f]

    cmd = [
        tshark, "-r", str(pcap),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=y",
        "-E", "occurrence=f",   # take first value when field repeats
        "-E", "aggregator=|",   # join multiple values with |
    ] + field_args

    print(f"  tshark filter: {display_filter!r}  ({len(fields)} fields)")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"  WARNING: tshark exit {result.returncode}: {result.stderr[:300]}")
    return result.stdout

# ──────────────────────────────────────────────────────────────────────────────
# Data extraction
# ──────────────────────────────────────────────────────────────────────────────

def _ip_filter(client_ip: str | None) -> str:
    """Build an IP restriction clause for a display filter."""
    if not client_ip:
        return ""
    return f" && (ip.src == {client_ip} || ip.dst == {client_ip})"


def extract_nfs(tshark: str, pcap: Path, client_ip: str | None = None) -> pd.DataFrame:
    """Return raw NFS packet DataFrame from pcap."""
    filt = "rpc.program == 100003" + _ip_filter(client_ip)
    out = run_tshark(tshark, pcap, filt, TSHARK_NFS_FIELDS)
    if not out.strip():
        return pd.DataFrame()

    df = pd.read_csv(StringIO(out), sep="\t", low_memory=False)
    df.columns = ["timestamp", "src", "dst", "msgtyp",
                  "proc_v3", "proc_v4", "rpc_time", "xid", "nfs_count"]

    for col in ["timestamp", "msgtyp", "proc_v3", "proc_v4", "rpc_time", "nfs_count"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Resolve operation name (v3 takes precedence; fall back to v4)
    df["op_num"] = df["proc_v3"].fillna(df["proc_v4"])
    df["op_name"] = df["op_num"].apply(
        lambda x: NFS3_OPS.get(int(x), f"OP_{int(x)}") if pd.notna(x) else "UNKNOWN"
    )
    return df.dropna(subset=["timestamp"])


def extract_smb2(tshark: str, pcap: Path, client_ip: str | None = None) -> pd.DataFrame:
    """Return raw SMB2 packet DataFrame from pcap."""
    filt = "smb2" + _ip_filter(client_ip)
    out = run_tshark(tshark, pcap, filt, TSHARK_SMB2_FIELDS)
    if not out.strip():
        return pd.DataFrame()

    df = pd.read_csv(StringIO(out), sep="\t", low_memory=False)
    df.columns = ["timestamp", "src", "dst", "is_response",
                  "cmd", "smb2_time", "msg_id",
                  "smb2_read_bytes", "smb2_write_bytes"]

    for col in ["timestamp", "is_response", "cmd", "smb2_time",
                "smb2_read_bytes", "smb2_write_bytes"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["op_name"] = df["cmd"].apply(
        lambda x: SMB2_CMDS.get(int(x), f"CMD_{int(x)}") if pd.notna(x) else "UNKNOWN"
    )
    return df.dropna(subset=["timestamp"])


def build_ops_df(raw: pd.DataFrame, protocol: str) -> pd.DataFrame:
    """
    Convert raw packet rows into one row per completed operation with columns:
      timestamp   — when the REQUEST was issued (seconds, epoch)
      latency_ms  — round-trip time in milliseconds
      op_name     — operation type string
      size_bytes  — payload bytes for READ/WRITE ops (NaN for others)

    Strategy: use REPLY packets that carry the response-time field.
    Request timestamp = reply_timestamp - rpc/smb2_time.
    """
    if raw.empty:
        return pd.DataFrame()

    if protocol == "nfs":
        replies = raw[raw["msgtyp"] == 1].dropna(subset=["rpc_time"]).copy()
        if replies.empty:
            return pd.DataFrame()
        replies["timestamp"]  = replies["timestamp"] - replies["rpc_time"]
        replies["latency_ms"] = replies["rpc_time"] * 1000
        replies["size_bytes"] = replies["nfs_count"]
        return replies[["timestamp", "latency_ms", "op_name", "size_bytes"]].reset_index(drop=True)

    elif protocol == "smb2":
        responses = raw[raw["is_response"] == 1].dropna(subset=["smb2_time"]).copy()
        if responses.empty:
            return pd.DataFrame()
        responses["timestamp"]  = responses["timestamp"] - responses["smb2_time"]
        responses["latency_ms"] = responses["smb2_time"] * 1000
        # READ response carries smb2_read_bytes; WRITE response carries smb2_write_bytes
        responses["size_bytes"] = responses["smb2_read_bytes"].fillna(responses["smb2_write_bytes"])
        return responses[["timestamp", "latency_ms", "op_name", "size_bytes"]].reset_index(drop=True)

    return pd.DataFrame()

# ──────────────────────────────────────────────────────────────────────────────
# Core analysis
# ──────────────────────────────────────────────────────────────────────────────

def _percentile(series: pd.Series, p: float) -> float:
    arr = series.dropna().values
    return float(np.percentile(arr, p)) if len(arr) > 0 else float("nan")


def lat_stats(series: pd.Series) -> dict:
    arr = series.dropna()
    if arr.empty:
        return {}
    return {
        "n": int(len(arr)),
        "mean_ms": round(float(arr.mean()), 3),
        "p50_ms":  round(_percentile(arr, 50), 3),
        "p95_ms":  round(_percentile(arr, 95), 3),
        "p99_ms":  round(_percentile(arr, 99), 3),
        "max_ms":  round(float(arr.max()), 3),
    }


def analyze(
    df: pd.DataFrame,
    window_ms: int = 10,
    burst_sigma: float = 2.0,
    ops_filter: list[str] | None = None,
) -> dict | None:
    """
    Core burst analysis.

    Steps:
      1. Optionally filter to specific operation types.
      2. Divide the trace timeline into fixed-size windows.
      3. Count requests per window; compute per-window latency stats.
      4. Classify each window as 'burst' if its count exceeds
         mean + burst_sigma * std_dev.
      5. Compare latency distributions in burst vs. non-burst windows.
      6. Compute burstiness metrics: CV, Fano factor, burst ratio.

    Returns a dict with keys: windows, df, summary, latency, op_breakdown.
    """
    if df.empty:
        return None

    if ops_filter:
        df = df[df["op_name"].isin(ops_filter)].copy()
        if df.empty:
            return None

    # Active window: from the first REQUEST to the last RESPONSE.
    # Using last-response (= request_ts + latency) avoids under-counting
    # when the capture has idle time at the start or end of the file.
    min_t = df["timestamp"].min()                                    # first request
    last_response_t = (df["timestamp"] + df["latency_ms"] / 1000).max()  # last response
    duration_sec = last_response_t - min_t
    if duration_sec <= 0:
        return None

    window_sec = window_ms / 1000.0
    n_windows = max(1, int(np.ceil(duration_sec / window_sec)))

    df = df.copy()
    df["win"] = (
        ((df["timestamp"] - min_t) / window_sec)
        .astype(int)
        .clip(0, n_windows - 1)
    )

    # Per-window aggregation
    agg = df.groupby("win").agg(
        req_count=("timestamp", "count"),
        mean_lat=("latency_ms", "mean"),
        p50_lat=("latency_ms", lambda x: _percentile(x, 50)),
        p95_lat=("latency_ms", lambda x: _percentile(x, 95)),
        p99_lat=("latency_ms", lambda x: _percentile(x, 99)),
    ).reset_index()

    # Fill windows with zero activity
    windows = (
        pd.DataFrame({"win": range(n_windows)})
        .merge(agg, on="win", how="left")
    )
    windows["req_count"] = windows["req_count"].fillna(0).astype(int)
    windows["time_ms"] = windows["win"] * window_ms

    counts = windows["req_count"]
    mean_c = float(counts.mean())
    std_c  = float(counts.std())
    burst_threshold = mean_c + burst_sigma * std_c
    windows["is_burst"] = windows["req_count"] > burst_threshold

    # Burstiness metrics
    #   CV > 1      → high variability relative to mean
    #   Fano > 1    → super-Poisson (clustered arrivals)
    #   burst_ratio → how many times peak exceeds mean
    cv           = std_c / mean_c if mean_c > 0 else 0.0
    fano         = counts.var() / mean_c if mean_c > 0 else 0.0
    burst_ratio  = (float(counts.max()) - mean_c) / mean_c if mean_c > 0 else 0.0

    # Latency split
    burst_idx    = windows.loc[windows["is_burst"], "win"]
    nonburst_idx = windows.loc[~windows["is_burst"] & (windows["req_count"] > 0), "win"]

    burst_lats    = df.loc[df["win"].isin(burst_idx),    "latency_ms"].dropna()
    nonburst_lats = df.loc[df["win"].isin(nonburst_idx), "latency_ms"].dropna()

    # Mann-Whitney U: are burst latencies stochastically greater?
    mw_result = None
    if len(burst_lats) >= 5 and len(nonburst_lats) >= 5:
        stat, pval = stats.mannwhitneyu(burst_lats, nonburst_lats, alternative="greater")
        mw_result = {"statistic": float(stat), "p_value": float(pval)}

    # ── Load-level latency groups ─────────────────────────────────────────────
    # Sort active windows by request count and split into three percentile bands.
    # This avoids arbitrary burst thresholds and directly answers:
    # "Does latency get worse as request rate increases?"
    active_wins = windows[windows["req_count"] > 0].copy()
    active_wins = active_wins.sort_values("req_count")
    n_active    = len(active_wins)

    def _win_group(lo_pct: float, hi_pct: float) -> dict:
        """Return latency stats + req_count range for windows in [lo_pct, hi_pct)."""
        lo = int(np.floor(lo_pct / 100 * n_active))
        hi = int(np.ceil( hi_pct / 100 * n_active))
        hi = max(hi, lo + 1)   # at least one window
        group_wins = active_wins.iloc[lo:hi]
        win_ids    = set(group_wins["win"])
        lats       = df.loc[df["win"].isin(win_ids), "latency_ms"].dropna()
        cnt_min    = int(group_wins["req_count"].min())
        cnt_max    = int(group_wins["req_count"].max())
        cnt_range  = f"{cnt_min}" if cnt_min == cnt_max else f"{cnt_min}–{cnt_max}"
        return {
            "win_count":  len(group_wins),
            "ops_range":  cnt_range,
            "latency":    lat_stats(lats),
        }

    load_groups = {
        "light":  _win_group(0,  10),   # quietest 10 %
        "normal": _win_group(45, 55),   # middle 10 %
        "heavy":  _win_group(90, 100),  # busiest 10 %
    }

    # ── Average READ / WRITE op size ──────────────────────────────────────────
    def _avg_size_kb(op: str) -> float | None:
        """Return average op size in KiB for a given op_name, or None if no data."""
        s = df.loc[df["op_name"] == op, "size_bytes"].dropna()
        return round(float(s.mean()) / 1024, 1) if not s.empty else None

    avg_read_size_kb  = _avg_size_kb("READ")
    avg_write_size_kb = _avg_size_kb("WRITE")

    # Overall average latency across all ops (all op types combined)
    avg_latency_ms = round(float(df["latency_ms"].mean()), 3) if not df["latency_ms"].dropna().empty else None

    return {
        "windows":     windows,
        "df":          df,
        "load_groups": load_groups,
        "summary": {
            "duration_sec":         round(duration_sec, 3),
            # duration_sec = last_response_time − first_request_time
            # (excludes idle time at the beginning/end of the capture)
            "total_ops":            int(len(df)),
            "avg_latency_ms":       avg_latency_ms,
            "avg_read_size_kb":     avg_read_size_kb,
            "avg_write_size_kb":    avg_write_size_kb,
            "window_ms":            window_ms,
            "n_windows":            n_windows,
            "mean_ops_per_window":  round(mean_c, 2),
            "mean_ops_per_sec":     round(mean_c / window_sec, 1),
            "peak_ops_per_window":  int(counts.max()),
            "p90_ops_per_window":   round(p90_window, 1),
            "p95_ops_per_window":   round(p95_window, 1),
            "peak_to_mean_ratio":   round(peak_to_mean, 1),
            "burst_threshold":      round(burst_threshold, 2),
            "n_burst_windows":      int(windows["is_burst"].sum()),
            "burst_pct":            round(float(windows["is_burst"].mean()) * 100, 1),
            "top_burst_windows":    top_windows,
            "cv":                   round(cv, 4),
            "fano_factor":          round(fano, 4),
            "burst_ratio":          round(burst_ratio, 4),
            # Verdict thresholds: CV>1 or Fano>2 both indicate significant burstiness
            "is_bursty":            cv > 1.0 or fano > 2.0,
        },
        "latency": {
            "overall":      lat_stats(df["latency_ms"]),
        },
        "op_breakdown": df["op_name"].value_counts().to_dict(),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Visualization  (4-panel figure)
# ──────────────────────────────────────────────────────────────────────────────

def plot_analysis(result: dict, protocol: str, out_path: Path) -> None:
    windows = result["windows"]
    df      = result["df"]
    s       = result["summary"]
    lat     = result["latency"]

    # Pre-compute burst / non-burst masks on the ops DataFrame
    burst_wins    = set(windows.loc[windows["is_burst"], "win"])
    nonburst_wins = set(windows.loc[~windows["is_burst"] & (windows["req_count"] > 0), "win"])
    is_burst_op    = df["win"].isin(burst_wins)
    is_nonburst_op = df["win"].isin(nonburst_wins)

    min_t = df["timestamp"].min()   # relative-time anchor

    fig = plt.figure(figsize=(16, 14))
    fig.suptitle(
        f"{protocol.upper()} Burstiness Analysis\n"
        f"Duration: {s['duration_sec']:.1f}s | "
        f"Ops: {s['total_ops']:,} | "
        f"Avg: {s['mean_ops_per_sec']:.0f} ops/s | "
        f"CV={s['cv']:.2f} | Fano={s['fano_factor']:.2f} | "
        f"{'⚠ BURSTY' if s['is_bursty'] else '✓ Normal'}",
        fontsize=13, fontweight="bold",
    )

    gs = gridspec.GridSpec(4, 2, figure=fig, hspace=0.55, wspace=0.35)

    # ── Panel 1: Request rate over time (full width) ───────────────────────────
    ax1 = fig.add_subplot(gs[0, :])
    t_s = windows["time_ms"] / 1000
    w_s = s["window_ms"] / 1000
    bm  = windows["is_burst"]

    ax1.bar(t_s[~bm], windows["req_count"][~bm], width=w_s,
            color="steelblue", alpha=0.7, label="Normal")
    ax1.bar(t_s[bm],  windows["req_count"][bm],  width=w_s,
            color="crimson", alpha=0.9, label="Burst")
    ax1.axhline(s["burst_threshold"], color="orange", linestyle="--",
                linewidth=1.5, label=f"Threshold ({s['burst_threshold']:.1f})")
    ax1.axhline(s["mean_ops_per_window"], color="green", linestyle=":",
                linewidth=1.2, label=f"Mean ({s['mean_ops_per_window']:.1f})")
    ax1.set_xlabel("Time (seconds)")
    ax1.set_ylabel(f"Ops / {s['window_ms']}ms window")
    ax1.set_title("① Request Rate Over Time  (red = burst windows)")
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(True, alpha=0.3)

    # ── Panel 2: Individual op latency scatter (full width) ────────────────────
    # Each dot = one completed operation.  Burst ops in red, normal ops in blue.
    # This immediately shows *when* latency spikes occur and their magnitude.
    ax2 = fig.add_subplot(gs[1, :])
    t_nb = df.loc[is_nonburst_op, "timestamp"] - min_t
    t_b  = df.loc[is_burst_op,    "timestamp"] - min_t
    l_nb = df.loc[is_nonburst_op, "latency_ms"]
    l_b  = df.loc[is_burst_op,    "latency_ms"]

    ax2.scatter(t_nb, l_nb, s=4, alpha=0.35, color="steelblue",
                label=f"Normal (n={len(l_nb):,})", rasterized=True)
    ax2.scatter(t_b,  l_b,  s=6, alpha=0.7,  color="crimson",
                label=f"Burst  (n={len(l_b):,})", rasterized=True)

    # Overlay running median (rolling p50) for trend clarity
    if not df.empty:
        sorted_df = df.sort_values("timestamp")
        roll_win  = max(20, len(sorted_df) // 200)   # adaptive window
        rolling_p50 = sorted_df["latency_ms"].rolling(roll_win, center=True, min_periods=1).median()
        ax2.plot(sorted_df["timestamp"] - min_t, rolling_p50,
                 color="gold", lw=1.5, alpha=0.9, label=f"Rolling p50 (w={roll_win})")

    ax2.set_xlabel("Time (seconds)")
    ax2.set_ylabel("Latency (ms)")
    ax2.set_title("② Per-Operation Latency Over Time  (each dot = 1 op)")
    ax2.legend(loc="upper right", fontsize=9)
    ax2.grid(True, alpha=0.2)

    # ── Panel 3: Per-window p50 + p95 lines (full width) ──────────────────────
    # Shows the rolling percentile trend without noise of individual ops.
    ax3 = fig.add_subplot(gs[2, :])
    valid = windows.dropna(subset=["p50_lat"])
    if not valid.empty:
        t3 = valid["time_ms"] / 1000
        ax3.plot(t3, valid["p50_lat"], color="steelblue", lw=1.2,
                 marker=".", markersize=3, label="p50 per window")
        ax3.plot(t3, valid["p95_lat"].fillna(np.nan), color="darkorange", lw=1.2,
                 marker=".", markersize=3, label="p95 per window")
        ax3.fill_between(t3,
                         valid["p50_lat"],
                         valid["p95_lat"].fillna(valid["p50_lat"]),
                         alpha=0.12, color="orange", label="p50–p95 band")
        # Shade burst windows
        for _, row in windows[windows["is_burst"]].iterrows():
            ax3.axvspan(row["time_ms"] / 1000,
                        (row["time_ms"] + s["window_ms"]) / 1000,
                        alpha=0.12, color="red")
    ax3.set_xlabel("Time (seconds)")
    ax3.set_ylabel("Latency (ms)")
    ax3.set_title(
        f"③ p50 / p95 per {s['window_ms']} ms Window  (red shading = burst windows)"
    )
    ax3.legend(fontsize=9)
    ax3.grid(True, alpha=0.3)

    # ── Panel 4 (left): Latency by load level — 3-group bar chart ────────────
    # Light (0-10%) / Normal (45-55%) / Heavy (90-100%) windows by request rate.
    # Each cluster shows p50 / p95 / p99 — easy to explain to anyone.
    ax4  = fig.add_subplot(gs[3, 0])
    lg   = result.get("load_groups", {})
    pcts     = ["p50", "p95", "p99"]
    pct_keys = ["p50_ms", "p95_ms", "p99_ms"]
    groups   = [
        ("Light\n(0–10%)",   lg.get("light",  {}).get("latency", {}), "#5BA4CF"),
        ("Normal\n(45–55%)", lg.get("normal", {}).get("latency", {}), "#F0A500"),
        ("Heavy\n(90–100%)", lg.get("heavy",  {}).get("latency", {}), "#D94F3D"),
    ]

    x     = np.arange(len(pcts))
    width = 0.25
    for i, (label, lat_d, color) in enumerate(groups):
        vals = [lat_d.get(k) or 0 for k in pct_keys]
        bars = ax4.bar(x + (i - 1) * width, vals, width,
                       color=color, alpha=0.85, label=label)
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax4.text(bar.get_x() + bar.get_width() / 2, h * 1.02,
                         f"{h:.1f}", ha="center", va="bottom", fontsize=7)

    ax4.set_xticks(x)
    ax4.set_xticklabels(pcts)
    ax4.set_ylabel("Latency (ms)")
    ax4.set_title("④ Latency by Load Level\n(grouped by ops per window)", fontsize=10)
    ax4.legend(fontsize=8, loc="upper left")
    ax4.grid(True, alpha=0.3, axis="y")

    # ── Panel 5 (right): Operation breakdown ──────────────────────────────────
    ax5 = fig.add_subplot(gs[3, 1])
    op_counts = df["op_name"].value_counts().head(12)
    bars5 = ax5.barh(op_counts.index[::-1], op_counts.values[::-1],
                     color="steelblue", alpha=0.8)
    ax5.set_xlabel("Count")
    ax5.set_title("⑤ Top Operations")
    ax5.grid(True, alpha=0.3, axis="x")
    for bar, val in zip(bars5, op_counts.values[::-1]):
        ax5.text(bar.get_width() * 1.01, bar.get_y() + bar.get_height() / 2,
                 f"{val:,}", va="center", fontsize=8)

    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart → {out_path}")

# ──────────────────────────────────────────────────────────────────────────────
# Text report
# ──────────────────────────────────────────────────────────────────────────────

def _ratio_tag(ratio: float) -> str:
    """Human-readable multiplier string, e.g. '8.3×'."""
    if ratio <= 0:
        return "N/A"
    return f"{ratio:.1f}×"


def print_report(result: dict, protocol: str) -> None:
    s   = result["summary"]
    lat = result["latency"]
    W   = s["window_ms"]
    sep = "─" * 66

    print(f"\n{'═' * 66}")
    print(f"  {protocol.upper()} BURSTINESS ANALYSIS REPORT")
    print(f"{'═' * 66}")

    # ── Section 1: Plain-language summary (for customer presentations) ────────
    print(f"\n  SUMMARY  (suitable for customer / management presentation)")
    print(sep)
    print(f"  Active duration  :  {s['duration_sec']:.1f} s  "
          f"(first request → last response, excludes capture idle time)")
    print(f"  Total operations :  {s['total_ops']:,}")
    print()

    # Average latency & op sizes — the first numbers a customer wants to see
    avg_lat = s.get("avg_latency_ms")
    if avg_lat is not None:
        print(f"  Average latency  :  {avg_lat:.3f} ms  (all operations)")
    avg_r = s.get("avg_read_size_kb")
    avg_w = s.get("avg_write_size_kb")
    if avg_r is not None or avg_w is not None:
        r_str = f"READ  {avg_r:>7.1f} KiB" if avg_r is not None else ""
        w_str = f"WRITE {avg_w:>7.1f} KiB" if avg_w is not None else ""
        parts = "   ".join(p for p in [r_str, w_str] if p)
        print(f"  Avg op size      :  {parts}")
    print()
    print(f"  Request rate per {W} ms window")
    print(f"    Average          :  {s['mean_ops_per_window']:.1f} ops  "
          f"({s['mean_ops_per_sec']:.0f} ops/s)")
    print(f"    Typical busy     :  {s['p90_ops_per_window']:.0f} ops  (90th-percentile window)")
    print(f"    Peak             :  {s['peak_ops_per_window']} ops  "
          f"— {_ratio_tag(s['peak_to_mean_ratio'])} the average")
    print()

    # Burst period count / fraction
    nb = s["n_burst_windows"]
    nw = s["n_windows"]
    bp = s["burst_pct"]
    print(f"  Burst periods      :  {nb} out of {nw} windows ({bp:.1f}% of the time)")
    print(f"  Burst threshold    :  > {s['burst_threshold']:.0f} ops/{W} ms")

    # ── Latency by load level ─────────────────────────────────────────────────
    lg = result.get("load_groups", {})
    if lg:
        print()
        print(f"  Latency by load level  "
              f"(windows grouped by ops/{W}ms, lightest → busiest)")
        print(f"  {'Group':<22}  {'Ops/'+str(W)+'ms':>10}  "
              f"{'p50':>10}  {'p95':>10}  {'p99':>10}")
        print(f"  {'-'*22}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

        light_p95 = lg["light"]["latency"].get("p95_ms") or 0
        rows = [
            ("Light load  (0–10%)",   lg["light"]),
            ("Normal load (45–55%)",  lg["normal"]),
            ("Heavy load  (90–100%)", lg["heavy"]),
        ]
        for label, grp in rows:
            lat_d  = grp["latency"]
            p50    = lat_d.get("p50_ms")
            p95    = lat_d.get("p95_ms")
            p99    = lat_d.get("p99_ms")
            p50_s  = f"{p50:>8.2f} ms" if p50 is not None else "       N/A"
            p95_s  = f"{p95:>8.2f} ms" if p95 is not None else "       N/A"
            p99_s  = f"{p99:>8.2f} ms" if p99 is not None else "       N/A"
            print(f"  {label:<22}  {grp['ops_range']:>10}  {p50_s}  {p95_s}  {p99_s}")

        # Verdict based on heavy vs light p95
        heavy_p95 = lg["heavy"]["latency"].get("p95_ms") or 0
        if light_p95 > 0 and heavy_p95 > 0:
            ratio = heavy_p95 / light_p95
            print()
            if ratio >= 2.0:
                print(f"  ⚠  Heavy-load p95 is {ratio:.1f}× higher than light-load p95 "
                      f"({light_p95:.2f} ms → {heavy_p95:.2f} ms).")
                print(f"     High request rate is degrading latency.")
            elif ratio >= 1.2:
                print(f"  △  Heavy-load p95 is {ratio:.1f}× light-load p95 "
                      f"({light_p95:.2f} ms → {heavy_p95:.2f} ms)  — moderate impact.")
            else:
                print(f"  ✓  Latency is stable across load levels "
                      f"(p95: {light_p95:.2f} ms → {heavy_p95:.2f} ms).")
                print(f"     The storage system handles high request rates well.")

    if s["is_bursty"]:
        print(f"\n  ⚠   CONCLUSION: Request rate is bursty "
              f"(peak {_ratio_tag(s['peak_to_mean_ratio'])} the average).")
    else:
        print(f"\n  ✓   CONCLUSION: No significant burstiness detected.")

    # ── Section 2: Top burst windows (concrete evidence) ─────────────────────
    top = s.get("top_burst_windows", [])
    if top:
        print(f"\n  Top {len(top)} busiest {W} ms windows")
        print(f"  {'Time (s)':>10}   {'Ops':>6}   {'p95 lat (ms)':>14}")
        print(f"  {'-'*10}   {'-'*6}   {'-'*14}")
        for w in top:
            t_s   = w["time_ms"] / 1000
            p95   = w.get("p95_lat")
            p95_s = f"{p95:>12.2f}" if p95 and not np.isnan(p95) else "          N/A"
            print(f"  {t_s:>10.3f}   {w['req_count']:>6}   {p95_s}")

    # ── Section 3: Overall latency table ─────────────────────────────────────
    print(f"\n  LATENCY TABLE  (all operations)")
    print(sep)

    def fmt(d: dict, label: str) -> str:
        if not d:
            return f"  {label:14s}  (no data)"
        return (f"  {label:14s}  n={d.get('n', 0):>7,}  "
                f"p50={d.get('p50_ms', 0):>8.2f} ms  "
                f"p95={d.get('p95_ms', 0):>8.2f} ms  "
                f"p99={d.get('p99_ms', 0):>8.2f} ms  "
                f"max={d.get('max_ms', 0):>8.2f} ms")

    print(fmt(lat.get("overall"), "Overall"))

    # ── Section 4: Operation breakdown ───────────────────────────────────────
    print(f"\n  OPERATION BREAKDOWN  (top 10)")
    print(sep)
    for op, cnt in sorted(result["op_breakdown"].items(), key=lambda x: -x[1])[:10]:
        pct = cnt / s["total_ops"] * 100
        bar = "█" * max(1, int(pct / 2))
        print(f"  {op:22s}  {cnt:>8,}  {pct:5.1f}%  {bar}")

    print(f"\n{'═' * 66}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

# Module-level sigma reference for report formatting
args_sigma: float = 2.0


def main() -> None:
    global args_sigma

    parser = argparse.ArgumentParser(
        description="Analyze NFS/CIFS packet traces for bursty workloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pcap",
                        help="pcap / pcapng capture file")
    parser.add_argument("--protocol", choices=["nfs", "smb2", "auto"],
                        default="auto",
                        help="Protocol to analyze (default: auto-detect both)")
    parser.add_argument("--window", type=int, default=10, metavar="MS",
                        help="Time window size in milliseconds (default: 10)")
    parser.add_argument("--sigma", type=float, default=2.0, metavar="N",
                        help="Burst threshold = mean + N×σ (default: 2.0)")
    parser.add_argument("--ops", nargs="+", metavar="OP",
                        help="Filter to specific operations e.g. READ WRITE")
    parser.add_argument("--client", metavar="IP",
                        help="Restrict to traffic involving this client IP")
    parser.add_argument("--tshark", metavar="PATH",
                        help="Path to tshark executable")
    parser.add_argument("--output", metavar="DIR", default=".",
                        help="Output directory for plots (default: current dir)")
    parser.add_argument("--json", metavar="FILE",
                        help="Save analysis results as JSON")
    parser.add_argument("--no-plot", action="store_true",
                        help="Skip chart generation")
    parser.add_argument("--list-ops", action="store_true",
                        help="List all operation types found and exit")

    args = parser.parse_args()
    args_sigma = args.sigma

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"ERROR: File not found: {pcap}")

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    tshark = args.tshark or find_tshark()
    if not tshark:
        checked = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "tshark (PATH)",
        ]
        print("ERROR: tshark not found. Checked:")
        for p in checked:
            print(f"  {p}")
        print("\nFix options:")
        print(r'  1. Add Wireshark to PATH: $env:PATH += ";C:\Program Files\Wireshark"')
        print(r'  2. Use --tshark flag:     python burst_analyzer.py capture.pcap --tshark "C:\Program Files\Wireshark\tshark.exe"')
        sys.exit(1)
    print(f"tshark: {tshark}")

    protocols = ["nfs", "smb2"] if args.protocol == "auto" else [args.protocol]
    all_results: dict[str, dict] = {}

    for proto in protocols:
        print(f"\n{'─' * 50}")
        print(f"Extracting {proto.upper()} …")

        if proto == "nfs":
            raw = extract_nfs(tshark, pcap, args.client)
        else:
            raw = extract_smb2(tshark, pcap, args.client)

        if raw.empty:
            print(f"  No {proto.upper()} traffic found.")
            continue
        print(f"  Packets: {len(raw):,}")

        ops_df = build_ops_df(raw, proto)
        if ops_df.empty:
            print(f"  No completed operations (no reply packets).")
            continue
        print(f"  Completed ops: {len(ops_df):,}")

        if args.list_ops:
            print(f"\n  Operations found in {proto.upper()}:")
            for op, cnt in ops_df["op_name"].value_counts().items():
                print(f"    {op:22s}  {cnt:,}")
            continue

        print(f"  Analyzing with {args.window}ms windows, σ={args.sigma} …")
        result = analyze(ops_df,
                         window_ms=args.window,
                         burst_sigma=args.sigma,
                         ops_filter=args.ops)
        if result is None:
            print("  Analysis failed.")
            continue

        all_results[proto] = result
        print_report(result, proto)

        if not args.no_plot:
            try:
                chart = out_dir / f"{pcap.stem}_{proto}_burst.png"
                plot_analysis(result, proto, chart)
            except Exception as exc:
                print(f"  WARNING: plot failed: {exc}")

    if not all_results and not args.list_ops:
        sys.exit("No NFS or SMB2 traffic found in the capture file.")

    if args.json and all_results:
        payload: dict = {}
        for proto, result in all_results.items():
            payload[proto] = {
                "summary":      result["summary"],
                "latency":      result["latency"],
                "op_breakdown": result["op_breakdown"],
            }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"JSON results → {args.json}")

    print("Done.")


if __name__ == "__main__":
    main()
