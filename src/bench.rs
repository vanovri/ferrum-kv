use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use crate::aof::FsyncPolicy;
use crate::cli::read_one_frame;
use crate::error::{EngineError, EngineResult};
use crate::resp::{
    encode_command_slices, write_i64_decimal, write_usize_decimal, OwnedFrame, ParseStatus,
    RespParser, StreamReadBuffer,
};
use crate::server::{FerrumServer, ServerConfig};

pub const DEFAULT_BENCH_CLIENTS: usize = 50;
pub const DEFAULT_BENCH_REQUESTS: usize = 100_000;
pub const DEFAULT_BENCH_PIPELINE: usize = 16;

#[derive(Clone, Debug)]
pub struct BenchConfig {
    pub target_addr: Option<String>,
    pub clients: usize,
    pub total_requests: usize,
    pub pipeline_depth: usize,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            target_addr: None,
            clients: DEFAULT_BENCH_CLIENTS,
            total_requests: DEFAULT_BENCH_REQUESTS,
            pipeline_depth: DEFAULT_BENCH_PIPELINE,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum WorkloadKind {
    Set,
    Get,
    ZAdd,
    EvalSha,
    VSearch,
    MixedTriad,
}

impl WorkloadKind {
    fn label(&self) -> &'static str {
        match self {
            WorkloadKind::Set => "SET (100% String Write)",
            WorkloadKind::Get => "GET (100% Zero-Copy Read)",
            WorkloadKind::ZAdd => "ZADD (100% SkipList Update)",
            WorkloadKind::EvalSha => "EVALSHA (Cached SHA-256 Bytecode VM)",
            WorkloadKind::VSearch => "VSEARCH (HNSW SQ8 Cosine k=5)",
            WorkloadKind::MixedTriad => "MIXED (SET / GET / ZADD Pipelined)",
        }
    }
}

pub fn run_benchmark_suite(cfg: BenchConfig) -> EngineResult<()> {
    let clients = cfg.clients.max(1);
    let total_requests = cfg.total_requests.max(clients);
    let pipeline = cfg.pipeline_depth.max(1);

    let mut embedded_server: Option<FerrumServer> = None;
    let addr = match &cfg.target_addr {
        Some(a) => a.clone(),
        None => {
            let mut server_cfg = ServerConfig::default();
            server_cfg.bind_addr = "127.0.0.1:0".to_string();
            server_cfg.aof_path = None;
            server_cfg.aof_fsync = FsyncPolicy::No;
            server_cfg.snapshot_path = PathBuf::from("ferrum_bench_unused.snap");
            let srv = FerrumServer::start(server_cfg)?;
            let bound = srv.local_addr().to_string();
            embedded_server = Some(srv);
            bound
        }
    };

    let script_sha = seed_benchmark_fixtures(&addr)?;

    println!("========================================================================");
    println!(" FerrumKV Capstone Benchmark Suite (Pure Rust `std` | Zero External Crates)");
    println!(" Target Endpoint   : {}", addr);
    println!(" Concurrent Clients: {} threads", clients);
    println!(" Requests / Phase  : {} pipelined ops", total_requests);
    println!(" Pipeline Depth    : {} cmds/batch", pipeline);
    println!("========================================================================");

    for workload in [
        WorkloadKind::Set,
        WorkloadKind::Get,
        WorkloadKind::ZAdd,
        WorkloadKind::EvalSha,
        WorkloadKind::VSearch,
    ] {
        // HNSW graph search performs multi-layer float/SQ8 distance math per op; cap default sample count at 20k so bench stays crisp while still exercising 50 concurrent threads.
        let phase_requests = match workload {
            WorkloadKind::VSearch => total_requests.min(20_000).max(clients),
            _ => total_requests,
        };
        run_single_workload(
            &addr,
            clients,
            phase_requests,
            pipeline,
            workload,
            &script_sha,
        )?;
    }

    run_single_workload(
        &addr,
        clients,
        total_requests,
        pipeline,
        WorkloadKind::MixedTriad,
        &script_sha,
    )?;

    if let Some(mut srv) = embedded_server {
        srv.shutdown();
    }
    Ok(())
}

fn seed_benchmark_fixtures(addr: &str) -> EngineResult<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut rbuf = StreamReadBuffer::with_capacity(8192);

    // 1. Load bytecode script for EVALSHA benchmark
    let script = b"let v = call(\"INCR\", KEYS[1]); return v + 1;";
    let mut wbuf = Vec::new();
    encode_command_slices(&mut wbuf, &[b"SCRIPT", b"LOAD", script]);
    stream.write_all(&wbuf)?;
    let sha_hex = match read_one_frame(&mut stream, &mut rbuf)? {
        OwnedFrame::BulkString(b) | OwnedFrame::SimpleString(b) => {
            String::from_utf8_lossy(&b).into_owned()
        }
        other => {
            return Err(EngineError::Protocol(format!(
                "unexpected SCRIPT LOAD response: {:?}",
                other
            )))
        }
    };

    // 2. Seed 128 8-D vectors into `bench:hnsw` for VSEARCH benchmark
    for i in 0..128usize {
        let id = format!("vec:{i}");
        let mut floats = Vec::with_capacity(8);
        for d in 0..8usize {
            let angle = ((i * 17 + d * 31) % 360) as f64 * 0.017_453_292_5;
            floats.push(format!("{:.4}", angle.sin() + 0.1 * (d as f64)));
        }
        let mut cmd: Vec<&[u8]> = Vec::with_capacity(11);
        cmd.push(b"VADD");
        cmd.push(b"bench:hnsw");
        cmd.push(id.as_bytes());
        for f in &floats {
            cmd.push(f.as_bytes());
        }
        wbuf.clear();
        encode_command_slices(&mut wbuf, &cmd);
        stream.write_all(&wbuf)?;
        let _ = read_one_frame(&mut stream, &mut rbuf)?;
    }

    Ok(sha_hex)
}

fn run_single_workload(
    addr: &str,
    clients: usize,
    total_requests: usize,
    pipeline: usize,
    workload: WorkloadKind,
    script_sha: &str,
) -> EngineResult<()> {
    let barrier = Arc::new(Barrier::new(clients + 1));
    let base_ops = total_requests / clients;
    let remainder = total_requests % clients;

    let mut handles = Vec::with_capacity(clients);
    for tid in 0..clients {
        let ops_for_thread = base_ops + usize::from(tid < remainder);
        let endpoint = addr.to_string();
        let sha_copy = script_sha.to_string();
        let bar = Arc::clone(&barrier);

        let handle = thread::Builder::new()
            .name(format!("bench-client-{tid}"))
            .spawn(move || -> EngineResult<Vec<u64>> {
                client_worker(
                    tid,
                    &endpoint,
                    ops_for_thread,
                    pipeline,
                    workload,
                    &sha_copy,
                    &bar,
                )
            })?;
        handles.push(handle);
    }

    barrier.wait();
    let wall_start = Instant::now();

    let mut all_latencies_ns: Vec<u64> = Vec::with_capacity(total_requests);
    for handle in handles {
        let thread_res = handle
            .join()
            .map_err(|_| EngineError::LockPoisoned("benchmark client thread panicked"))?;
        let samples = thread_res?;
        all_latencies_ns.extend(samples);
    }

    let elapsed = wall_start.elapsed();
    print_latency_report(workload.label(), &mut all_latencies_ns, elapsed);
    Ok(())
}

fn client_worker(
    tid: usize,
    endpoint: &str,
    total_ops: usize,
    pipeline: usize,
    workload: WorkloadKind,
    script_sha: &str,
    barrier: &Barrier,
) -> EngineResult<Vec<u64>> {
    let mut stream = TcpStream::connect(endpoint)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut read_buf = StreamReadBuffer::with_capacity(64 * 1024);
    let mut write_buf = Vec::with_capacity(pipeline * 96);
    let mut key_scratch = Vec::with_capacity(32);
    let mut val_scratch = Vec::with_capacity(32);
    let mut score_scratch = Vec::with_capacity(24);
    let mut latencies_ns = Vec::with_capacity(total_ops);

    barrier.wait();

    let mut completed = 0usize;
    while completed < total_ops {
        let batch = (total_ops - completed).min(pipeline);
        write_buf.clear();

        for offset in 0..batch {
            let seq = completed + offset;
            let global_key_id = (tid * 2048) + (seq & 2047);

            match workload {
                WorkloadKind::Set => {
                    key_scratch.clear();
                    key_scratch.extend_from_slice(b"bench:str:");
                    write_usize_decimal(&mut key_scratch, global_key_id);

                    val_scratch.clear();
                    val_scratch.extend_from_slice(b"payload_v_");
                    write_usize_decimal(&mut val_scratch, seq);

                    encode_command_slices(&mut write_buf, &[b"SET", &key_scratch, &val_scratch]);
                }
                WorkloadKind::Get => {
                    key_scratch.clear();
                    key_scratch.extend_from_slice(b"bench:str:");
                    write_usize_decimal(&mut key_scratch, global_key_id);

                    encode_command_slices(&mut write_buf, &[b"GET", &key_scratch]);
                }
                WorkloadKind::ZAdd => {
                    key_scratch.clear();
                    key_scratch.extend_from_slice(b"bench:zset:");
                    write_usize_decimal(&mut key_scratch, tid & 15);

                    score_scratch.clear();
                    write_i64_decimal(&mut score_scratch, (seq % 10_000) as i64);

                    val_scratch.clear();
                    val_scratch.extend_from_slice(b"member:");
                    write_usize_decimal(&mut val_scratch, global_key_id);

                    encode_command_slices(
                        &mut write_buf,
                        &[b"ZADD", &key_scratch, &score_scratch, &val_scratch],
                    );
                }
                WorkloadKind::EvalSha => {
                    key_scratch.clear();
                    key_scratch.extend_from_slice(b"bench:vm:");
                    write_usize_decimal(&mut key_scratch, tid);

                    encode_command_slices(
                        &mut write_buf,
                        &[b"EVALSHA", script_sha.as_bytes(), b"1", &key_scratch],
                    );
                }
                WorkloadKind::VSearch => {
                    encode_command_slices(
                        &mut write_buf,
                        &[
                            b"VSEARCH",
                            b"bench:hnsw",
                            b"5",
                            b"0.25",
                            b"0.35",
                            b"0.45",
                            b"0.55",
                            b"0.65",
                            b"0.75",
                            b"0.85",
                            b"0.95",
                        ],
                    );
                }
                WorkloadKind::MixedTriad => match seq % 3 {
                    0 => {
                        key_scratch.clear();
                        key_scratch.extend_from_slice(b"bench:str:");
                        write_usize_decimal(&mut key_scratch, global_key_id);

                        val_scratch.clear();
                        val_scratch.extend_from_slice(b"payload_v_");
                        write_usize_decimal(&mut val_scratch, seq);

                        encode_command_slices(
                            &mut write_buf,
                            &[b"SET", &key_scratch, &val_scratch],
                        );
                    }
                    1 => {
                        key_scratch.clear();
                        key_scratch.extend_from_slice(b"bench:str:");
                        write_usize_decimal(&mut key_scratch, global_key_id);
                        encode_command_slices(&mut write_buf, &[b"GET", &key_scratch]);
                    }
                    _ => {
                        key_scratch.clear();
                        key_scratch.extend_from_slice(b"bench:zset:");
                        write_usize_decimal(&mut key_scratch, tid & 15);

                        score_scratch.clear();
                        write_i64_decimal(&mut score_scratch, (seq % 10_000) as i64);

                        val_scratch.clear();
                        val_scratch.extend_from_slice(b"member:");
                        write_usize_decimal(&mut val_scratch, global_key_id);

                        encode_command_slices(
                            &mut write_buf,
                            &[b"ZADD", &key_scratch, &score_scratch, &val_scratch],
                        );
                    }
                },
            }
        }

        let t0 = Instant::now();
        stream.write_all(&write_buf)?;

        let mut replies = 0usize;
        while replies < batch {
            loop {
                match RespParser::parse(read_buf.readable_slice())? {
                    ParseStatus::Complete { consumed, .. } => {
                        read_buf.consume(consumed);
                        let op_ns = (t0.elapsed().as_nanos() as u64).max(1);
                        latencies_ns.push(op_ns);
                        replies += 1;
                        if replies == batch {
                            break;
                        }
                    }
                    ParseStatus::Incomplete => break,
                }
            }
            if replies < batch {
                let dst = read_buf.writable_slice(8192);
                match stream.read(dst) {
                    Ok(0) => {
                        return Err(EngineError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "server closed connection during benchmark pipeline",
                        )))
                    }
                    Ok(n) => read_buf.advance_write(n),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(EngineError::Io(err)),
                }
            }
        }

        completed += batch;
    }

    Ok(latencies_ns)
}

fn print_latency_report(title: &str, samples_ns: &mut [u64], wall_elapsed: Duration) {
    if samples_ns.is_empty() {
        return;
    }
    samples_ns.sort_unstable();

    let count = samples_ns.len();
    let secs = wall_elapsed.as_secs_f64().max(1e-9);
    let rps = (count as f64) / secs;

    let min_us = samples_ns[0] as f64 / 1_000.0;
    let p50_us = percentile_ns(samples_ns, 0.50) as f64 / 1_000.0;
    let p95_us = percentile_ns(samples_ns, 0.95) as f64 / 1_000.0;
    let p99_us = percentile_ns(samples_ns, 0.99) as f64 / 1_000.0;
    let p999_us = percentile_ns(samples_ns, 0.999) as f64 / 1_000.0;
    let max_us = samples_ns[count - 1] as f64 / 1_000.0;
    let sum_ns: u128 = samples_ns.iter().map(|&x| x as u128).sum();
    let mean_us = (sum_ns as f64 / count as f64) / 1_000.0;

    println!("\n------------------------------------------------------------------------");
    println!(" Workload   : {}", title);
    println!(
        " Completed  : {} requests in {:.2} ms ({:.0} req/sec)",
        count,
        secs * 1000.0,
        rps
    );
    println!(
        " Latency us : min={:.2} | mean={:.2} | p50={:.2} | p95={:.2} | p99={:.2} | p99.9={:.2} | max={:.2}",
        min_us, mean_us, p50_us, p95_us, p99_us, p999_us, max_us
    );
    println!(" Histogram  :");

    let buckets_us: &[(u64, &str)] = &[
        (10, "<=   10 us"),
        (25, "<=   25 us"),
        (50, "<=   50 us"),
        (100, "<=  100 us"),
        (250, "<=  250 us"),
        (500, "<=  500 us"),
        (1_000, "<= 1000 us"),
        (u64::MAX, ">  1000 us"),
    ];

    let mut counts = [0usize; 8];
    for &ns in samples_ns.iter() {
        let us = ns / 1_000;
        for (idx, &(upper, _)) in buckets_us.iter().enumerate() {
            if us <= upper {
                counts[idx] += 1;
                break;
            }
        }
    }

    let bar_width = 36usize;
    for (idx, &(_, label)) in buckets_us.iter().enumerate() {
        let c = counts[idx];
        if c == 0 {
            continue;
        }
        let pct = (c as f64 * 100.0) / (count as f64);
        let filled = ((pct / 100.0) * (bar_width as f64)).round() as usize;
        let bar = "#".repeat(filled.max(1));
        println!("   {} | {:6.2}% ({:7}) | {}", label, pct, c, bar);
    }
}

#[inline]
fn percentile_ns(sorted: &[u64], q: f64) -> u64 {
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
