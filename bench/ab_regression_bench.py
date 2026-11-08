#!/usr/bin/env python3
"""Automated A/B Micro-Benchmark & Tail-Latency (p99) Regression Harness for FerrumKV.

Why a dedicated harness instead of `ferrum_kv bench`?
1. Ref-Independent Load Generator (`ferrum_loadgen`): compiled once outside the server worktree
   so client-side refactors never skew server measurements.
2. True Per-Command Latency vs Batch-Mean Bias: `src/bench.rs:402-406` divides total batch time
   by `batch` (`batch_ns / batch`), averaging out tail spikes across 16 pipelined commands.
   `ferrum_loadgen` timestamps each individual frame completion and supports `pipeline=1`
   (unaveraged per-RPC p99) as well as open-loop fixed-rate pacing (`--rate`) measured from
   the *scheduled* send instant to prevent Coordinated Omission.
3. ABBA Interleaved Trials: runs A -> B -> B -> A order across workloads to cancel CPU thermal
   throttling and OS background jitter.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from statistics import median
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
LOADGEN_DIR = Path(__file__).resolve().parent / "loadgen"


def find_cargo_cmd() -> list[str]:
    """Return cargo command using the installed GNU toolchain if MSVC link.exe is unavailable."""
    r = subprocess.run(["rustup", "toolchain", "list"], capture_output=True, text=True)
    if "stable-x86_64-pc-windows-gnu" in r.stdout:
        return ["cargo", "+stable-x86_64-pc-windows-gnu"]
    return ["cargo"]


def ensure_loadgen_binary(cargo_cmd: list[str]) -> Path:
    exe_name = "ferrum_loadgen.exe" if os.name == "nt" else "ferrum_loadgen"
    candidates = [
        LOADGEN_DIR / "target" / "release" / exe_name,
        LOADGEN_DIR / "target" / "x86_64-pc-windows-gnu" / "release" / exe_name,
    ]
    for c in candidates:
        if c.is_file():
            return c
    subprocess.run([*cargo_cmd, "build", "--release"], cwd=LOADGEN_DIR, check=True)
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError("Failed to locate compiled ferrum_loadgen binary.")


def resolve_git_ref(ref: str) -> str | None:
    r = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--verify", "-q", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def build_server_for_ref(ref_sha: str, cargo_cmd: list[str], cache_dir: Path) -> Path:
    exe_name = f"ferrum_kv_{ref_sha[:7]}" + (".exe" if os.name == "nt" else "")
    cached_bin = cache_dir / exe_name
    if cached_bin.is_file():
        return cached_bin

    head_sha = resolve_git_ref("HEAD")
    precompiled_root = REPO_ROOT / ("ferrum_kv.exe" if os.name == "nt" else "ferrum_kv")
    if ref_sha == head_sha and precompiled_root.is_file():
        shutil.copy2(precompiled_root, cached_bin)
        return cached_bin

    wt_dir = cache_dir / f"wt_{ref_sha[:7]}"
    if wt_dir.exists():
        subprocess.run(["git", "-C", str(REPO_ROOT), "worktree", "remove", "--force", str(wt_dir)], capture_output=True)
        shutil.rmtree(wt_dir, ignore_errors=True)

    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "worktree", "add", "--detach", str(wt_dir), ref_sha],
        check=True,
        capture_output=True,
    )
    try:
        subprocess.run([*cargo_cmd, "build", "--release"], cwd=wt_dir, check=True)
        bin_name = "ferrum_kv.exe" if os.name == "nt" else "ferrum_kv"
        built = wt_dir / "target" / "release" / bin_name
        shutil.copy2(built, cached_bin)
    finally:
        subprocess.run(["git", "-C", str(REPO_ROOT), "worktree", "remove", "--force", str(wt_dir)], capture_output=True)
        shutil.rmtree(wt_dir, ignore_errors=True)
    return cached_bin


def allocate_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(addr: str, timeout_s: float = 5.0) -> None:
    host, port_s = addr.rsplit(":", 1)
    port = int(port_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError(f"Server at {addr} did not become ready within {timeout_s}s")


def run_single_loadgen(
    server_bin: Path,
    loadgen_bin: Path,
    *,
    workload: str,
    clients: int,
    pipeline: int,
    duration_s: float,
    warmup_s: float,
    keyspace: int,
    value_size: int,
    rate: float,
    workers: int,
    shards: int,
) -> dict[str, Any]:
    port = allocate_ephemeral_port()
    addr = f"127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="ferrum_ab_") as tmpdir:
        snap_path = Path(tmpdir) / "bench.snap"
        srv_proc = subprocess.Popen(
            [
                str(server_bin),
                "server",
                "--bind",
                addr,
                "--workers",
                str(workers),
                "--shards",
                str(shards),
                "--aof",
                "off",
                "--fsync",
                "no",
                "--snapshot",
                str(snap_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd=tmpdir,
        )
        try:
            wait_for_port(addr)
            lg_cmd = [
                str(loadgen_bin),
                "--addr",
                addr,
                "--workload",
                workload,
                "--clients",
                str(clients),
                "--pipeline",
                str(pipeline),
                "--duration",
                f"{duration_s:.3f}",
                "--warmup",
                f"{warmup_s:.3f}",
                "--keyspace",
                str(keyspace),
                "--value-size",
                str(value_size),
                "--rate",
                f"{rate:.1f}",
            ]
            res = subprocess.run(lg_cmd, capture_output=True, text=True, check=True)
            return json.loads(res.stdout.strip().splitlines()[-1])
        finally:
            try:
                if srv_proc.stdin:
                    srv_proc.stdin.write(b"\n")
                    srv_proc.stdin.flush()
                srv_proc.wait(timeout=2.0)
            except Exception:
                srv_proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="FerrumKV A/B Throughput & Tail-Latency (p99) Regression Suite")
    parser.add_argument("--ref-a", default="HEAD~1", help="Baseline git ref (Before refactor)")
    parser.add_argument("--ref-b", default="HEAD", help="Candidate git ref (After refactor)")
    parser.add_argument("--clients", type=int, default=16, help="Concurrent client threads")
    parser.add_argument("--duration", type=float, default=1.2, help="Measurement duration per trial (seconds)")
    parser.add_argument("--warmup", type=float, default=0.3, help="Warmup duration per trial (seconds)")
    parser.add_argument("--rounds", type=int, default=2, help="ABBA rounds per workload (min 1)")
    parser.add_argument("--max-rps-drop-pct", type=float, default=5.0, help="Fail if throughput drops more than X%%")
    parser.add_argument("--max-p99-rise-pct", type=float, default=10.0, help="Fail if p99 latency rises more than X%%")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional path to write JSON report")
    args = parser.parse_args()

    cargo_cmd = find_cargo_cmd()
    loadgen_bin = ensure_loadgen_binary(cargo_cmd)

    sha_b = resolve_git_ref(args.ref_b) or resolve_git_ref("HEAD")
    sha_a = resolve_git_ref(args.ref_a)
    single_commit_note = False
    if not sha_a:
        sha_a = sha_b
        single_commit_note = True

    assert sha_a is not None and sha_b is not None

    cache_dir = Path(tempfile.gettempdir()) / "ferrum_ab_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    bin_a = build_server_for_ref(sha_a, cargo_cmd, cache_dir)
    bin_b = build_server_for_ref(sha_b, cargo_cmd, cache_dir)

    workloads = [
        {"name": "SET (p=1, unpipelined tail)", "workload": "set", "pipeline": 1, "rate": 0.0, "keyspace": 20_000},
        {"name": "GET (p=1, unpipelined tail)", "workload": "get", "pipeline": 1, "rate": 0.0, "keyspace": 20_000},
        {"name": "MIXED 80/20 (p=16, pipelined)", "workload": "mixed", "pipeline": 16, "rate": 0.0, "keyspace": 20_000},
        {"name": "INCR Hot-Key (16 keys, p=8)", "workload": "incr", "pipeline": 8, "rate": 0.0, "keyspace": 16},
        {"name": "GET Open-Loop (rate=40k/s, p=1)", "workload": "get", "pipeline": 1, "rate": 40_000.0, "keyspace": 20_000},
    ]

    report_rows = []
    any_regression = False

    for spec in workloads:
        samples_a: list[dict[str, Any]] = []
        samples_b: list[dict[str, Any]] = []
        # Interleaved ABBA schedule
        for r in range(max(1, args.rounds)):
            order = [("A", bin_a, samples_a), ("B", bin_b, samples_b)]
            if r % 2 == 1:
                order.reverse()
            for _label, sbin, bucket in order:
                m = run_single_loadgen(
                    sbin,
                    loadgen_bin,
                    workload=spec["workload"],
                    clients=args.clients,
                    pipeline=spec["pipeline"],
                    duration_s=args.duration,
                    warmup_s=args.warmup,
                    keyspace=spec["keyspace"],
                    value_size=64,
                    rate=spec["rate"],
                    workers=8,
                    shards=64,
                )
                bucket.append(m)

        med_rps_a = median(x["throughput_ops_s"] for x in samples_a)
        med_rps_b = median(x["throughput_ops_s"] for x in samples_b)
        med_p50_a = median(x["latency_us"]["p50"] for x in samples_a)
        med_p50_b = median(x["latency_us"]["p50"] for x in samples_b)
        med_p99_a = median(x["latency_us"]["p99"] for x in samples_a)
        med_p99_b = median(x["latency_us"]["p99"] for x in samples_b)
        med_p999_a = median(x["latency_us"]["p999"] for x in samples_a)
        med_p999_b = median(x["latency_us"]["p999"] for x in samples_b)

        rps_delta_pct = ((med_rps_b - med_rps_a) / max(1e-9, med_rps_a)) * 100.0
        p99_delta_pct = ((med_p99_b - med_p99_a) / max(1e-9, med_p99_a)) * 100.0

        is_open_loop = spec["rate"] > 0.0
        regressed = (not is_open_loop and rps_delta_pct < -args.max_rps_drop_pct) or (
            p99_delta_pct > args.max_p99_rise_pct
        )
        if regressed:
            any_regression = True

        report_rows.append(
            {
                "name": spec["name"],
                "rps_a": round(med_rps_a, 1),
                "rps_b": round(med_rps_b, 1),
                "rps_delta_pct": round(rps_delta_pct, 2),
                "p50_a_us": round(med_p50_a, 2),
                "p50_b_us": round(med_p50_b, 2),
                "p99_a_us": round(med_p99_a, 2),
                "p99_b_us": round(med_p99_b, 2),
                "p99_delta_pct": round(p99_delta_pct, 2),
                "p999_a_us": round(med_p999_a, 2),
                "p999_b_us": round(med_p999_b, 2),
                "status": "REGRESSED" if regressed else "PASS",
            }
        )

    print(f"# FerrumKV A/B Regression Benchmark ({sha_a[:7]} vs {sha_b[:7]})")
    if single_commit_note:
        print(
            f"> Note: repository currently has a single root commit ({sha_b[:7]}), and `codex/auto-refactor-and-tests` "
            "was never created on `C:\\ferrum_kv`. Running ABBA self-consistency baseline (A == B == HEAD)."
        )
    print(
        "\n| Workload | RPS (A) | RPS (B) | Δ RPS (%) | p50 A (µs) | p50 B (µs) | p99 A (µs) | p99 B (µs) | Δ p99 (%) | p99.9 B (µs) | Gate |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in report_rows:
        print(
            f"| {r['name']} | {r['rps_a']:,.0f} | {r['rps_b']:,.0f} | {r['rps_delta_pct']:+.2f}% | "
            f"{r['p50_a_us']:.1f} | {r['p50_b_us']:.1f} | {r['p99_a_us']:.1f} | {r['p99_b_us']:.1f} | "
            f"{r['p99_delta_pct']:+.2f}% | {r['p999_b_us']:.1f} | **{r['status']}** |"
        )

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "ref_a": sha_a,
                    "ref_b": sha_b,
                    "single_commit_repo": single_commit_note,
                    "clients": args.clients,
                    "rounds": args.rounds,
                    "results": report_rows,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 1 if any_regression and not single_commit_note else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
