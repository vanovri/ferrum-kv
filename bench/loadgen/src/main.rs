//! Ref-independent RESP2/RESP3 load generator for FerrumKV A/B regression benchmarks.
//!
//! Why not reuse `ferrum_kv bench`?
//!   1. It is compiled from the ref under test, so a refactor of the client code would
//!      silently change the measuring instrument.
//!   2. It records `batch_elapsed / batch_len` for every op in a pipeline, which averages
//!      away the tail: p99 there is really "p99 of batch means".
//!   3. It is closed-loop only, so it suffers from coordinated omission.
//!
//! This tool records per-request latency (send time of the batch -> arrival of *that*
//! reply), supports an open-loop fixed-rate mode measured from the *intended* send time,
//! and stores samples in a log-linear histogram (<0.8% relative error).

use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- histogram

const SUB_BITS: u32 = 7; // 128 sub-buckets per power of two
const SUB_COUNT: usize = 1 << SUB_BITS;
const LINEAR_LIMIT: u64 = 1 << (SUB_BITS + 1); // values < 256 ns stored exactly
const MAX_EXP: u32 = 44; // ~4.8 hours in ns, far beyond any sane latency
const BUCKETS: usize = LINEAR_LIMIT as usize + ((MAX_EXP - SUB_BITS) as usize) * SUB_COUNT;

#[derive(Clone)]
struct Histogram {
    counts: Vec<u64>,
    total: u64,
    sum_ns: u128,
    max_ns: u64,
}

impl Histogram {
    fn new() -> Self {
        Self { counts: vec![0; BUCKETS], total: 0, sum_ns: 0, max_ns: 0 }
    }

    #[inline]
    fn index_of(v: u64) -> usize {
        if v < LINEAR_LIMIT {
            return v as usize;
        }
        let exp = 63 - v.leading_zeros(); // >= SUB_BITS + 1
        let exp = exp.min(MAX_EXP);
        let shift = exp - SUB_BITS;
        let sub = ((v >> shift) as usize) & (SUB_COUNT - 1);
        let idx = LINEAR_LIMIT as usize + ((exp - SUB_BITS - 1) as usize) * SUB_COUNT + sub;
        idx.min(BUCKETS - 1)
    }

    /// Midpoint of the value range represented by bucket `idx`.
    fn value_of(idx: usize) -> u64 {
        if idx < LINEAR_LIMIT as usize {
            return idx as u64;
        }
        let rel = idx - LINEAR_LIMIT as usize;
        let exp = (rel / SUB_COUNT) as u32 + SUB_BITS + 1;
        let sub = (rel % SUB_COUNT) as u64;
        let shift = exp - SUB_BITS;
        let lo = (SUB_COUNT as u64 | sub) << shift;
        lo + ((1u64 << shift) >> 1)
    }

    #[inline]
    fn record(&mut self, v: u64) {
        self.counts[Self::index_of(v)] += 1;
        self.total += 1;
        self.sum_ns += v as u128;
        if v > self.max_ns {
            self.max_ns = v;
        }
    }

    fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a += *b;
        }
        self.total += other.total;
        self.sum_ns += other.sum_ns;
        self.max_ns = self.max_ns.max(other.max_ns);
    }

    fn quantile(&self, q: f64) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let rank = ((self.total as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (idx, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Self::value_of(idx).min(self.max_ns);
            }
        }
        self.max_ns
    }
}

// ---------------------------------------------------------------- config

#[derive(Clone, Copy, PartialEq, Eq)]
enum Workload {
    Set,
    Get,
    Mixed, // 80% GET / 20% SET
    Incr,  // hot-key contention: all clients hammer a tiny keyspace
}

#[derive(Clone)]
struct Config {
    addr: String,
    workload: Workload,
    clients: usize,
    pipeline: usize,
    duration: Duration,
    warmup: Duration,
    keyspace: u64,
    value_size: usize,
    rate: f64, // total ops/s; 0 = closed loop
    seed: u64,
    preload: bool,
}

fn usage() -> ! {
    eprintln!(
        "ferrum_loadgen --addr 127.0.0.1:6380 [--workload set|get|mixed|incr] [--clients 32] \
         [--pipeline 1] [--duration 10] [--warmup 2] [--keyspace 100000] [--value-size 64] \
         [--rate 0] [--seed 42] [--preload]"
    );
    process::exit(2);
}

fn parse_args() -> Config {
    let mut cfg = Config {
        addr: "127.0.0.1:6380".to_string(),
        workload: Workload::Mixed,
        clients: 32,
        pipeline: 1,
        duration: Duration::from_secs(10),
        warmup: Duration::from_secs(2),
        keyspace: 100_000,
        value_size: 64,
        rate: 0.0,
        seed: 42,
        preload: false,
    };
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--preload" {
            cfg.preload = true;
            i += 1;
            continue;
        }
        let Some(val) = args.get(i + 1) else { usage() };
        fn parse_or_die<T: std::str::FromStr>(flag: &str, val: &str) -> T {
            match val.parse::<T>() {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("invalid value for {flag}: {val}");
                    usage()
                }
            }
        }
        match flag {
            "--addr" => cfg.addr = val.clone(),
            "--workload" => {
                cfg.workload = match val.as_str() {
                    "set" => Workload::Set,
                    "get" => Workload::Get,
                    "mixed" => Workload::Mixed,
                    "incr" => Workload::Incr,
                    _ => usage(),
                }
            }
            "--clients" => cfg.clients = parse_or_die(flag, val),
            "--pipeline" => cfg.pipeline = parse_or_die(flag, val),
            "--duration" => cfg.duration = Duration::from_secs_f64(parse_or_die(flag, val)),
            "--warmup" => cfg.warmup = Duration::from_secs_f64(parse_or_die(flag, val)),
            "--keyspace" => cfg.keyspace = parse_or_die(flag, val),
            "--value-size" => cfg.value_size = parse_or_die(flag, val),
            "--rate" => cfg.rate = parse_or_die(flag, val),
            "--seed" => cfg.seed = parse_or_die(flag, val),
            _ => usage(),
        }
        i += 2;
    }
    cfg.clients = cfg.clients.max(1);
    cfg.pipeline = cfg.pipeline.max(1);
    cfg.keyspace = cfg.keyspace.max(1);
    cfg
}

// ---------------------------------------------------------------- RESP helpers

fn encode(out: &mut Vec<u8>, parts: &[&[u8]]) {
    out.push(b'*');
    out.extend_from_slice(parts.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    for p in parts {
        out.push(b'$');
        out.extend_from_slice(p.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(p);
        out.extend_from_slice(b"\r\n");
    }
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_int(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

/// Returns `Some((consumed, is_error))` when one complete RESP2/RESP3 frame is at `buf[pos..]`.
fn skip_frame(buf: &[u8], pos: usize) -> Option<(usize, bool)> {
    let tag = *buf.get(pos)?;
    let eol = find_crlf(buf, pos + 1)?;
    let line = &buf[pos + 1..eol];
    let after = eol + 2;
    match tag {
        b'+' | b':' | b'_' | b'#' | b',' | b'(' => Some((after - pos, false)),
        b'-' => Some((after - pos, true)),
        b'$' | b'!' | b'=' => {
            let n = parse_int(line)?;
            if n < 0 {
                return Some((after - pos, false));
            }
            let end = after + n as usize + 2;
            if buf.len() < end {
                return None;
            }
            Some((end - pos, tag == b'!'))
        }
        b'*' | b'~' | b'>' | b'%' | b'|' => {
            let n = parse_int(line)?;
            if n < 0 {
                return Some((after - pos, false));
            }
            let items = if tag == b'%' || tag == b'|' { n as usize * 2 } else { n as usize };
            let mut cur = after;
            let mut err = false;
            for _ in 0..items {
                let (c, e) = skip_frame(buf, cur)?;
                cur += c;
                err |= e;
            }
            Some((cur - pos, err))
        }
        _ => Some((after - pos, true)),
    }
}

// ---------------------------------------------------------------- workers

struct ThreadResult {
    hist: Histogram,
    ops: u64,
    errors: u64,
}

#[inline]
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn connect(addr: &str) -> io::Result<TcpStream> {
    let s = TcpStream::connect(addr)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(15)))?;
    Ok(s)
}

fn preload(cfg: &Config) -> io::Result<()> {
    let mut s = connect(&cfg.addr)?;
    let value = vec![b'x'; cfg.value_size];
    let mut out = Vec::with_capacity(64 * 1024);
    let mut inbuf = vec![0u8; 64 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    let chunk = 512u64;
    let mut k = 0u64;
    while k < cfg.keyspace {
        out.clear();
        let end = (k + chunk).min(cfg.keyspace);
        for id in k..end {
            let key = format!("lg:{id}");
            encode(&mut out, &[b"SET", key.as_bytes(), &value]);
        }
        s.write_all(&out)?;
        let mut need = (end - k) as usize;
        while need > 0 {
            let mut pos = 0;
            while need > 0 {
                match skip_frame(&pending, pos) {
                    Some((c, _)) => {
                        pos += c;
                        need -= 1;
                    }
                    None => break,
                }
            }
            pending.drain(..pos);
            if need > 0 {
                let n = s.read(&mut inbuf)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "preload EOF"));
                }
                pending.extend_from_slice(&inbuf[..n]);
            }
        }
        k = end;
    }
    Ok(())
}

fn worker(tid: usize, cfg: Config, barrier: Arc<Barrier>) -> io::Result<ThreadResult> {
    let mut stream = connect(&cfg.addr)?;
    let mut rng = cfg.seed ^ ((tid as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
    let value = vec![b'v'; cfg.value_size];
    let mut out = Vec::with_capacity(cfg.pipeline * (cfg.value_size + 64));
    let mut inbuf = vec![0u8; 256 * 1024];
    let mut pending: Vec<u8> = Vec::with_capacity(256 * 1024);
    let mut key = Vec::with_capacity(32);
    let mut hist = Histogram::new();
    let mut ops = 0u64;
    let mut errors = 0u64;

    // Open-loop pacing: each client owns rate/clients ops/s, issued in batches of `pipeline`.
    let per_client_rate = if cfg.rate > 0.0 { cfg.rate / cfg.clients as f64 } else { 0.0 };
    let batch_interval = if per_client_rate > 0.0 {
        Duration::from_secs_f64(cfg.pipeline as f64 / per_client_rate)
    } else {
        Duration::ZERO
    };

    barrier.wait();
    let start = Instant::now();
    let measure_from = start + cfg.warmup;
    let deadline = measure_from + cfg.duration;
    let mut batch_no: u64 = 0;

    loop {
        let intended = if per_client_rate > 0.0 {
            let t = start + batch_interval.mul_f64(batch_no as f64);
            let now = Instant::now();
            if t > now {
                let wait = t - now;
                if wait > Duration::from_micros(200) {
                    thread::sleep(wait - Duration::from_micros(100));
                }
                while Instant::now() < t {
                    std::hint::spin_loop();
                }
            }
            t
        } else {
            Instant::now()
        };
        if intended >= deadline {
            break;
        }
        batch_no += 1;

        out.clear();
        for _ in 0..cfg.pipeline {
            let r = xorshift(&mut rng);
            key.clear();
            key.extend_from_slice(b"lg:");
            let id = match cfg.workload {
                Workload::Incr => r % cfg.keyspace.min(16),
                _ => r % cfg.keyspace,
            };
            key.extend_from_slice(id.to_string().as_bytes());
            match cfg.workload {
                Workload::Set => encode(&mut out, &[b"SET", &key, &value]),
                Workload::Get => encode(&mut out, &[b"GET", &key]),
                Workload::Incr => {
                    key.extend_from_slice(b":ctr");
                    encode(&mut out, &[b"INCR", &key]);
                }
                Workload::Mixed => {
                    if (r >> 40) % 10 < 2 {
                        encode(&mut out, &[b"SET", &key, &value]);
                    } else {
                        encode(&mut out, &[b"GET", &key]);
                    }
                }
            }
        }

        let sent_at = Instant::now();
        // Closed loop measures from actual send; open loop from the intended schedule.
        let origin = if per_client_rate > 0.0 { intended } else { sent_at };
        stream.write_all(&out)?;

        let mut got = 0usize;
        while got < cfg.pipeline {
            let mut pos = 0usize;
            while got < cfg.pipeline {
                match skip_frame(&pending, pos) {
                    Some((c, is_err)) => {
                        pos += c;
                        got += 1;
                        let now = Instant::now();
                        if now >= measure_from {
                            hist.record((now - origin).as_nanos() as u64);
                            ops += 1;
                            if is_err {
                                errors += 1;
                            }
                        }
                    }
                    None => break,
                }
            }
            if pos > 0 {
                pending.drain(..pos);
            }
            if got < cfg.pipeline {
                let n = stream.read(&mut inbuf)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed"));
                }
                pending.extend_from_slice(&inbuf[..n]);
            }
        }

        if Instant::now() >= deadline {
            break;
        }
    }

    Ok(ThreadResult { hist, ops, errors })
}

fn main() {
    let cfg = parse_args();

    if cfg.preload || cfg.workload == Workload::Get || cfg.workload == Workload::Mixed {
        if let Err(e) = preload(&cfg) {
            eprintln!("preload failed: {e}");
            process::exit(1);
        }
    }

    let barrier = Arc::new(Barrier::new(cfg.clients));
    let mut handles = Vec::with_capacity(cfg.clients);
    for tid in 0..cfg.clients {
        let c = cfg.clone();
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || worker(tid, c, b)));
    }

    let mut hist = Histogram::new();
    let mut ops = 0u64;
    let mut errors = 0u64;
    let mut failures = 0usize;
    for h in handles {
        match h.join() {
            Ok(Ok(r)) => {
                hist.merge(&r.hist);
                ops += r.ops;
                errors += r.errors;
            }
            Ok(Err(e)) => {
                eprintln!("worker error: {e}");
                failures += 1;
            }
            Err(_) => failures += 1,
        }
    }

    let secs = cfg.duration.as_secs_f64();
    let us = |ns: u64| ns as f64 / 1000.0;
    let mean_us = if hist.total > 0 { (hist.sum_ns as f64 / hist.total as f64) / 1000.0 } else { 0.0 };
    let wl = match cfg.workload {
        Workload::Set => "set",
        Workload::Get => "get",
        Workload::Mixed => "mixed",
        Workload::Incr => "incr",
    };
    println!(
        "{{\"workload\":\"{wl}\",\"clients\":{},\"pipeline\":{},\"rate\":{},\"duration_s\":{secs:.3},\
\"ops\":{ops},\"errors\":{errors},\"worker_failures\":{failures},\"throughput_ops_s\":{:.1},\
\"latency_us\":{{\"mean\":{mean_us:.2},\"p50\":{:.2},\"p90\":{:.2},\"p99\":{:.2},\"p999\":{:.2},\"max\":{:.2}}}}}",
        cfg.clients,
        cfg.pipeline,
        cfg.rate,
        ops as f64 / secs,
        us(hist.quantile(0.50)),
        us(hist.quantile(0.90)),
        us(hist.quantile(0.99)),
        us(hist.quantile(0.999)),
        us(hist.max_ns),
    );
    if failures > 0 {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_relative_error_is_bounded() {
        let mut v: u64 = 1;
        while v < 10_000_000_000 {
            let got = Histogram::value_of(Histogram::index_of(v));
            let err = (got as f64 - v as f64).abs() / v as f64;
            assert!(err <= 1.0 / 128.0, "v={v} got={got} err={err}");
            v = v * 3 / 2 + 1;
        }
    }

    #[test]
    fn histogram_quantiles_match_exact_sort() {
        let mut h = Histogram::new();
        let mut xs: Vec<u64> = (0..10_000u64).map(|i| (i * 7919) % 1_000_003 + 300).collect();
        for &x in &xs {
            h.record(x);
        }
        xs.sort_unstable();
        for q in [0.5, 0.9, 0.99, 0.999] {
            let exact = xs[((xs.len() as f64 * q).ceil() as usize).max(1) - 1] as f64;
            let approx = h.quantile(q) as f64;
            assert!((approx - exact).abs() / exact <= 1.0 / 128.0, "q={q} exact={exact} approx={approx}");
        }
    }

    #[test]
    fn skip_frame_handles_resp2_and_resp3() {
        assert_eq!(skip_frame(b"+OK\r\n", 0), Some((5, false)));
        assert_eq!(skip_frame(b"-ERR x\r\n", 0), Some((8, true)));
        assert_eq!(skip_frame(b"$3\r\nabc\r\n", 0), Some((9, false)));
        assert_eq!(skip_frame(b"$3\r\nab", 0), None);
        assert_eq!(skip_frame(b"_\r\n", 0), Some((3, false)));
        assert_eq!(skip_frame(b"$-1\r\n", 0), Some((5, false)));
        assert_eq!(skip_frame(b"*2\r\n:1\r\n$1\r\na\r\n", 0), Some((15, false)));
        assert_eq!(skip_frame(b"%1\r\n+k\r\n-e\r\n", 0), Some((12, true)));
    }
}
