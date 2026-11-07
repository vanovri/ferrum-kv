#![forbid(unsafe_code)]

pub mod aof;
pub mod bench;
pub mod cli;
pub mod cluster;
pub mod error;
pub mod jepsen;
pub mod pubsub;
pub mod resp;
pub mod security;
pub mod server;
pub mod storage;
pub mod telemetry;
pub mod tx;
pub mod vm;

use std::env;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process;

use crate::aof::FsyncPolicy;
use crate::bench::{run_benchmark_suite, BenchConfig};
use crate::cli::run_interactive_cli;
use crate::error::{EngineError, EngineResult};
use crate::jepsen::run_jepsen_nemesis_suite;
use crate::server::{FerrumServer, ServerConfig};

fn main() {
    if let Err(err) = try_main() {
        eprintln!("[ferrum_kv fatal] {}", err);
        process::exit(1);
    }
}

fn try_main() -> EngineResult<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = args.first().map(|s| s.as_str()).unwrap_or("server");

    match mode {
        "server" => run_server_cmd(&args[usize::from(!args.is_empty())..]),
        "cli" => run_cli_cmd(&args[1..]),
        "bench" => run_bench_cmd(&args[1..]),
        "jepsen" => {
            let _ = run_jepsen_nemesis_suite(true)?;
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(EngineError::InvalidArgument(format!(
            "unknown mode '{}'. Run with --help for usage.",
            other
        ))),
    }
}

fn run_server_cmd(flags: &[String]) -> EngineResult<()> {
    let mut cfg = ServerConfig::default();
    let mut i = 0usize;
    while i < flags.len() {
        match flags[i].as_str() {
            "--bind" => {
                i += 1;
                cfg.bind_addr = next_flag_val("--bind", flags, i)?.to_string();
            }
            "--node-id" => {
                i += 1;
                cfg.node_id = next_flag_val("--node-id", flags, i)?.to_string();
            }
            "--workers" => {
                i += 1;
                cfg.worker_threads = next_flag_val("--workers", flags, i)?.parse()?;
            }
            "--shards" => {
                i += 1;
                cfg.shard_count = next_flag_val("--shards", flags, i)?.parse()?;
            }
            "--aof" => {
                i += 1;
                let v = next_flag_val("--aof", flags, i)?;
                if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
                    cfg.aof_path = None;
                } else {
                    cfg.aof_path = Some(PathBuf::from(v));
                }
            }
            "--fsync" => {
                i += 1;
                cfg.aof_fsync = FsyncPolicy::from_str_name(next_flag_val("--fsync", flags, i)?)?;
            }
            "--snapshot" => {
                i += 1;
                cfg.snapshot_path = PathBuf::from(next_flag_val("--snapshot", flags, i)?);
            }
            "--lsm-dir" => {
                i += 1;
                cfg.lsm_dir = Some(PathBuf::from(next_flag_val("--lsm-dir", flags, i)?));
            }
            other => {
                return Err(EngineError::InvalidArgument(format!(
                    "unknown server flag '{}'",
                    other
                )))
            }
        }
        i += 1;
    }

    let mut server = FerrumServer::start(cfg.clone())?;
    println!(
        "FerrumKV 5.0.0 listening on {} (node={}, workers={}, shards={}, fsync={:?})",
        server.local_addr(),
        cfg.node_id,
        cfg.worker_threads,
        cfg.shard_count,
        cfg.aof_fsync
    );
    println!("Press ENTER to initiate graceful shutdown...");

    let stdin = io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);

    println!("Shutting down FerrumKV...");
    server.shutdown();
    Ok(())
}

fn run_cli_cmd(flags: &[String]) -> EngineResult<()> {
    let mut addr = "127.0.0.1:6379".to_string();
    let mut i = 0usize;
    while i < flags.len() {
        match flags[i].as_str() {
            "--addr" => {
                i += 1;
                addr = next_flag_val("--addr", flags, i)?.to_string();
            }
            other => {
                return Err(EngineError::InvalidArgument(format!(
                    "unknown cli flag '{}'",
                    other
                )))
            }
        }
        i += 1;
    }
    run_interactive_cli(&addr)
}

fn run_bench_cmd(flags: &[String]) -> EngineResult<()> {
    let mut cfg = BenchConfig::default();
    let mut i = 0usize;
    while i < flags.len() {
        match flags[i].as_str() {
            "--addr" => {
                i += 1;
                cfg.target_addr = Some(next_flag_val("--addr", flags, i)?.to_string());
            }
            "--clients" => {
                i += 1;
                cfg.clients = next_flag_val("--clients", flags, i)?.parse()?;
            }
            "--requests" => {
                i += 1;
                cfg.total_requests = next_flag_val("--requests", flags, i)?.parse()?;
            }
            "--pipeline" => {
                i += 1;
                cfg.pipeline_depth = next_flag_val("--pipeline", flags, i)?.parse()?;
            }
            other => {
                return Err(EngineError::InvalidArgument(format!(
                    "unknown bench flag '{}'",
                    other
                )))
            }
        }
        i += 1;
    }
    run_benchmark_suite(cfg)
}

fn next_flag_val<'a>(flag: &str, flags: &'a [String], idx: usize) -> EngineResult<&'a str> {
    flags
        .get(idx)
        .map(|s| s.as_str())
        .ok_or_else(|| EngineError::InvalidArgument(format!("missing value after '{}'", flag)))
}

fn print_usage() {
    println!("FerrumKV 5.0.0 — Pure-Rust Zero-Crate Distributed RESP3, Raft, Vector/FTS, LSM & Time-Series Engine");
    println!();
    println!("USAGE:");
    println!("  ferrum_kv server [--bind 127.0.0.1:6379] [--node-id id] [--workers N] [--shards 64] [--aof ferrum.aof|off] [--fsync always|everysec|no] [--lsm-dir ./lsm]");
    println!("  ferrum_kv cli    [--addr 127.0.0.1:6379]");
    println!("  ferrum_kv bench  [--addr 127.0.0.1:6379] [--clients 50] [--requests 100000] [--pipeline 16]");
    println!("  ferrum_kv jepsen");
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::aof::{
        load_binary_snapshot, load_encrypted_snapshot, replay_aof, save_binary_snapshot,
        save_encrypted_snapshot,
    };
    use crate::cli::read_one_frame;
    use crate::cluster::raft::{PeerConfig, RaftRole};
    use crate::cluster::sharding::key_hash_slot;
    use crate::resp::{encode_command_slices, OwnedFrame, StreamReadBuffer};
    use crate::storage::StorageEngine;
    use crate::vm::sha256;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    fn send_cmd(
        stream: &mut TcpStream,
        rbuf: &mut StreamReadBuffer,
        parts: &[&[u8]],
    ) -> EngineResult<OwnedFrame> {
        let mut wbuf = Vec::new();
        encode_command_slices(&mut wbuf, parts);
        stream.write_all(&wbuf)?;
        read_one_frame(stream, rbuf)
    }

    #[test]
    fn test_phase1_structures_ttl_pubsub_aof_and_snapshot() -> EngineResult<()> {
        let temp_dir = env::temp_dir().join(format!("ferrum_kv_p1_{}", process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir)?;

        let aof_path = temp_dir.join("test.aof");
        let snap_path = temp_dir.join("test.snap");

        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            worker_threads: 4,
            shard_count: 16,
            ttl_sweep_interval: Duration::from_millis(30),
            aof_path: Some(aof_path.clone()),
            aof_fsync: FsyncPolicy::Always,
            snapshot_path: snap_path.clone(),
            max_pooled_buffers: 32,
            ..ServerConfig::default()
        };

        let mut server = FerrumServer::start(cfg)?;
        let addr = server.local_addr().to_string();

        let mut client = TcpStream::connect(&addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut rbuf = StreamReadBuffer::with_capacity(8192);

        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"SET", b"counter", b"10"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"INCRBY", b"counter", b"32"])?,
            OwnedFrame::Integer(42)
        );
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"SET", b"ephemeral", b"gone", b"PX", b"60"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        thread::sleep(Duration::from_millis(120));
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"GET", b"ephemeral"])?,
            OwnedFrame::Null
        );

        send_cmd(&mut client, &mut rbuf, &[b"RPUSH", b"jobs", b"j1", b"j2"])?;
        send_cmd(&mut client, &mut rbuf, &[b"LPUSH", b"jobs", b"j0"])?;
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"LRANGE", b"jobs", b"0", b"-1"])?,
            OwnedFrame::Array(vec![
                OwnedFrame::BulkString(b"j0".to_vec()),
                OwnedFrame::BulkString(b"j1".to_vec()),
                OwnedFrame::BulkString(b"j2".to_vec()),
            ])
        );

        assert_eq!(
            send_cmd(
                &mut client,
                &mut rbuf,
                &[b"HSET", b"user:1", b"name", b"Ada", b"role", b"architect"]
            )?,
            OwnedFrame::Integer(2)
        );
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"HGET", b"user:1", b"role"])?,
            OwnedFrame::BulkString(b"architect".to_vec())
        );

        assert_eq!(
            send_cmd(
                &mut client,
                &mut rbuf,
                &[b"ZADD", b"leaderboard", b"25.5", b"bob", b"99.0", b"alice", b"50.0", b"carol"]
            )?,
            OwnedFrame::Integer(3)
        );
        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"ZRANGE", b"leaderboard", b"0", b"-1"])?,
            OwnedFrame::Array(vec![
                OwnedFrame::BulkString(b"bob".to_vec()),
                OwnedFrame::BulkString(b"carol".to_vec()),
                OwnedFrame::BulkString(b"alice".to_vec()),
            ])
        );

        let mut sub_sock = TcpStream::connect(&addr)?;
        sub_sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut sub_rbuf = StreamReadBuffer::with_capacity(8192);
        let _ = send_cmd(&mut sub_sock, &mut sub_rbuf, &[b"PSUBSCRIBE", b"alerts.*"])?;

        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"PUBLISH", b"alerts.cpu", b"high"])?,
            OwnedFrame::Integer(1)
        );
        let pushed = read_one_frame(&mut sub_sock, &mut sub_rbuf)?;
        assert_eq!(
            pushed,
            OwnedFrame::Push(vec![
                OwnedFrame::BulkString(b"pmessage".to_vec()),
                OwnedFrame::BulkString(b"alerts.*".to_vec()),
                OwnedFrame::BulkString(b"alerts.cpu".to_vec()),
                OwnedFrame::BulkString(b"high".to_vec()),
            ])
        );
        drop(sub_sock);

        assert_eq!(
            send_cmd(&mut client, &mut rbuf, &[b"SAVE"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        let _ = send_cmd(&mut client, &mut rbuf, &[b"BGREWRITEAOF"])?;
        thread::sleep(Duration::from_millis(120));
        drop(client);
        server.shutdown();

        let fresh_from_aof = StorageEngine::new(8)?;
        let replayed = replay_aof(&aof_path, &fresh_from_aof)?;
        assert!(replayed >= 4);
        assert_eq!(fresh_from_aof.zcard(b"leaderboard")?, 3);

        let fresh_from_snap = StorageEngine::new(8)?;
        let snap_count = load_binary_snapshot(&snap_path, &fresh_from_snap)?;
        assert_eq!(snap_count, 4);
        let _ = save_binary_snapshot(&snap_path, &fresh_from_snap)?;

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_phase2_streams_probabilistic_geohash_and_watch_multi_exec() -> EngineResult<()> {
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            worker_threads: 4,
            shard_count: 16,
            aof_path: None,
            snapshot_path: env::temp_dir().join("ferrum_p2_unused.snap"),
            ..ServerConfig::default()
        };
        let mut server = FerrumServer::start(cfg)?;
        let addr = server.local_addr().to_string();

        let mut c1 = TcpStream::connect(&addr)?;
        c1.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut r1 = StreamReadBuffer::with_capacity(8192);

        // 1. Streams + Consumer Group PEL + XACK
        assert_eq!(
            send_cmd(
                &mut c1,
                &mut r1,
                &[b"XADD", b"events", b"1000-0", b"sensor", b"alpha"]
            )?,
            OwnedFrame::BulkString(b"1000-0".to_vec())
        );
        assert_eq!(
            send_cmd(
                &mut c1,
                &mut r1,
                &[b"XADD", b"events", b"1000-1", b"sensor", b"beta"]
            )?,
            OwnedFrame::BulkString(b"1000-1".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"XLEN", b"events"])?,
            OwnedFrame::Integer(2)
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"XGROUP", b"CREATE", b"events", b"cg1", b"0"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        let xrg = send_cmd(
            &mut c1,
            &mut r1,
            &[b"XREADGROUP", b"GROUP", b"cg1", b"workerA", b"COUNT", b"1", b"STREAMS", b"events", b">"],
        )?;
        assert!(matches!(xrg, OwnedFrame::Array(_)));
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"XACK", b"events", b"cg1", b"1000-0"])?,
            OwnedFrame::Integer(1)
        );

        // 2. HyperLogLog, BloomFilter, CountMinSketch
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"PFADD", b"uv", b"u1", b"u2", b"u3", b"u2"])?,
            OwnedFrame::Integer(1)
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"PFCOUNT", b"uv"])?,
            OwnedFrame::Integer(3)
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"BF.ADD", b"seen", b"tok_99"])?,
            OwnedFrame::Integer(1)
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"BF.EXISTS", b"seen", b"tok_99"])?,
            OwnedFrame::Integer(1)
        );
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"CMS.INCRBY", b"freq", b"ip1", b"7", b"ip2", b"2"])?,
            OwnedFrame::Array(vec![OwnedFrame::Integer(7), OwnedFrame::Integer(2)])
        );

        // 3. 52-bit Morton Geohash + WGS84 Haversine GEODIST + GEORADIUS
        assert_eq!(
            send_cmd(
                &mut c1,
                &mut r1,
                &[
                    b"GEOADD",
                    b"cities",
                    b"13.361389",
                    b"38.115556",
                    b"Palermo",
                    b"15.087269",
                    b"37.502669",
                    b"Catania",
                ]
            )?,
            OwnedFrame::Integer(2)
        );
        let dist_frame = send_cmd(
            &mut c1,
            &mut r1,
            &[b"GEODIST", b"cities", b"Palermo", b"Catania", b"km"],
        )?;
        match dist_frame {
            OwnedFrame::Double(km) => {
                assert!((km - 166.27).abs() < 1.5);
            }
            OwnedFrame::BulkString(b) => {
                let km: f64 = std::str::from_utf8(&b)?.parse()?;
                assert!((km - 166.27).abs() < 1.5);
            }
            other => return Err(EngineError::Protocol(format!("unexpected GEODIST: {other:?}"))),
        }
        assert_eq!(
            send_cmd(
                &mut c1,
                &mut r1,
                &[b"GEORADIUS", b"cities", b"15.0", b"37.9", b"200", b"km", b"ASC"]
            )?,
            OwnedFrame::Array(vec![
                OwnedFrame::BulkString(b"Catania".to_vec()),
                OwnedFrame::BulkString(b"Palermo".to_vec()),
            ])
        );

        // 4. Optimistic Concurrency WATCH conflict -> Null abort + clean MULTI/EXEC commit
        send_cmd(&mut c1, &mut r1, &[b"SET", b"acct:1", b"100"])?;
        send_cmd(&mut c1, &mut r1, &[b"WATCH", b"acct:1"])?;
        send_cmd(&mut c1, &mut r1, &[b"MULTI"])?;
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"INCRBY", b"acct:1", b"50"])?,
            OwnedFrame::SimpleString(b"QUEUED".to_vec())
        );

        // Concurrent client mutates watched key `acct:1`
        let mut c2 = TcpStream::connect(&addr)?;
        c2.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut r2 = StreamReadBuffer::with_capacity(4096);
        send_cmd(&mut c2, &mut r2, &[b"SET", b"acct:1", b"999"])?;
        drop(c2);

        // EXEC must abort with RESP3 Null
        assert_eq!(send_cmd(&mut c1, &mut r1, &[b"EXEC"])?, OwnedFrame::Null);
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"GET", b"acct:1"])?,
            OwnedFrame::BulkString(b"999".to_vec())
        );

        // Uncontended WATCH + MULTI + EXEC commits atomically
        send_cmd(&mut c1, &mut r1, &[b"WATCH", b"acct:1"])?;
        send_cmd(&mut c1, &mut r1, &[b"MULTI"])?;
        send_cmd(&mut c1, &mut r1, &[b"INCRBY", b"acct:1", b"1"])?;
        assert_eq!(
            send_cmd(&mut c1, &mut r1, &[b"EXEC"])?,
            OwnedFrame::Array(vec![OwnedFrame::Integer(1000)])
        );

        drop(c1);
        server.shutdown();
        let _ = fs::remove_file(env::temp_dir().join("ferrum_p2_unused.snap"));
        Ok(())
    }

    #[test]
    fn test_phase3_vm_hnsw_fts_and_encrypted_persistence_roundtrip() -> EngineResult<()> {
        let temp_dir = env::temp_dir().join(format!("ferrum_kv_p3_{}", process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir)?;

        let aof_path = temp_dir.join("p3.aof");
        let snap_path = temp_dir.join("p3.snap");
        let enc_snap_path = temp_dir.join("p3.snap.enc");

        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            worker_threads: 4,
            shard_count: 16,
            aof_path: Some(aof_path.clone()),
            aof_fsync: FsyncPolicy::Always,
            snapshot_path: snap_path.clone(),
            ..ServerConfig::default()
        };
        let mut server = FerrumServer::start(cfg)?;
        let addr = server.local_addr().to_string();

        let mut c = TcpStream::connect(&addr)?;
        c.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut r = StreamReadBuffer::with_capacity(8192);

        // 1. Embedded Bytecode VM (`SCRIPT LOAD` + `EVALSHA`)
        let script = b"let cur = call(\"INCRBY\", KEYS[1], ARGV[1]); return cur * 2;";
        let sha_frame = send_cmd(&mut c, &mut r, &[b"SCRIPT", b"LOAD", script])?;
        let OwnedFrame::BulkString(sha_hex) = sha_frame else {
            return Err(EngineError::Protocol("expected BulkString SHA-256".to_string()));
        };
        assert_eq!(sha_hex.len(), 64);
        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"EVALSHA", &sha_hex, b"1", b"vm:counter", b"21"])?,
            OwnedFrame::Integer(42)
        );

        // 2. HNSW Vector Index (`VADD` + `VSEARCH`)
        send_cmd(
            &mut c,
            &mut r,
            &[b"VADD", b"emb", b"doc_rust", b"1.0", b"0.0", b"0.0", b"SQ8"],
        )?;
        send_cmd(
            &mut c,
            &mut r,
            &[b"VADD", b"emb", b"doc_net", b"0.0", b"1.0", b"0.0", b"SQ8"],
        )?;
        let vres = send_cmd(
            &mut c,
            &mut r,
            &[b"VSEARCH", b"emb", b"1", b"0.98", b"0.02", b"0.0"],
        )?;
        match vres {
            OwnedFrame::Array(items) => {
                assert!(items.len() >= 2);
                assert_eq!(items[0], OwnedFrame::BulkString(b"doc_rust".to_vec()));
            }
            other => return Err(EngineError::Protocol(format!("unexpected VSEARCH: {other:?}"))),
        }

        // 3. Okapi BM25 Full-Text Search & Prefix Trie (`FT.ADD`, `FT.SEARCH`, `FT.SUGG`)
        send_cmd(
            &mut c,
            &mut r,
            &[b"FT.ADD", b"docs", b"d1", b"rust systems programming consensus raft"],
        )?;
        send_cmd(
            &mut c,
            &mut r,
            &[b"FT.ADD", b"docs", b"d2", b"distributed consensus raft state machine"],
        )?;
        let ft_res = send_cmd(&mut c, &mut r, &[b"FT.SEARCH", b"docs", b"rust", b"LIMIT", b"5"])?;
        match ft_res {
            OwnedFrame::Array(items) => {
                assert!(items.len() >= 2);
                assert_eq!(items[0], OwnedFrame::BulkString(b"d1".to_vec()));
            }
            other => return Err(EngineError::Protocol(format!("unexpected FT.SEARCH: {other:?}"))),
        }
        let sugg_res = send_cmd(&mut c, &mut r, &[b"FT.SUGG", b"docs", b"cons"])?;
        assert_eq!(
            sugg_res,
            OwnedFrame::Array(vec![OwnedFrame::BulkString(b"consensus".to_vec())])
        );

        // Add Stream, HLL & TimeSeries so all advanced structures round-trip through AOF & Encrypted Snapshot
        send_cmd(&mut c, &mut r, &[b"XADD", b"st", b"1-0", b"k", b"v"])?;
        send_cmd(&mut c, &mut r, &[b"PFADD", b"hll", b"a", b"b"])?;
        send_cmd(&mut c, &mut r, &[b"TS.ADD", b"cpu", b"1000", b"42.5"])?;

        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"SAVE"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"SAVE.ENCRYPTED", b"master-secret-key"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        drop(c);
        server.shutdown();

        // Verify AOF replay + ChaCha20-Poly1305 encrypted snapshot restoration
        let restored_aof = StorageEngine::new(8)?;
        let _ = replay_aof(&aof_path, &restored_aof)?;
        assert_eq!(restored_aof.vcard(b"emb")?, 2);
        assert_eq!(restored_aof.xlen(b"st")?, 1);
        assert_eq!(restored_aof.pfcount(&[b"hll"])?, 2);

        let key32 = sha256(b"master-secret-key");
        let restored_enc = StorageEngine::new(8)?;
        let loaded_keys = load_encrypted_snapshot(&enc_snap_path, &restored_enc, &key32)?;
        assert_eq!(loaded_keys, 6);
        assert_eq!(restored_enc.vcard(b"emb")?, 2);
        let _ = save_encrypted_snapshot(&enc_snap_path, &restored_enc, &key32)?;

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_phase4_raft_3node_partition_cluster_redirection_and_lsm() -> EngineResult<()> {
        let temp_dir = env::temp_dir().join(format!("ferrum_kv_p4_{}", process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir)?;
        let lsm_dir = temp_dir.join("lsm_data");

        // Spawn 3 TCP FerrumServer nodes with Raft + Cluster + LSM enabled on Node 0
        let mut nodes = Vec::with_capacity(3);
        let mut addrs = Vec::with_capacity(3);
        for i in 0..3 {
            let cfg = ServerConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                node_id: format!("n{}", i + 1),
                worker_threads: 3,
                shard_count: 8,
                aof_path: None,
                snapshot_path: temp_dir.join(format!("n{i}.snap")),
                lsm_dir: if i == 0 { Some(lsm_dir.clone()) } else { None },
                ..ServerConfig::default()
            };
            let srv = FerrumServer::start(cfg)?;
            addrs.push(srv.local_addr().to_string());
            nodes.push(srv);
        }

        for i in 0..3 {
            let mut peers = Vec::new();
            for j in 0..3 {
                if i != j {
                    peers.push(PeerConfig {
                        node_id: format!("n{}", j + 1),
                        addr: addrs[j].clone(),
                    });
                }
            }
            nodes[i].raft_node().configure_peers(peers)?;
        }

        // 1. Raft Election + Majority Propose + Partitioned Follower Catch-up
        assert!(nodes[0].raft_node().start_election()?);
        assert_eq!(nodes[0].raft_node().status()?.role, RaftRole::Leader);

        let mut c0 = TcpStream::connect(&addrs[0])?;
        c0.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut r0 = StreamReadBuffer::with_capacity(8192);

        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"RAFT.PROPOSE", b"SET", b"raft:k1", b"v1"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );

        // Partition follower n3, commit `raft:k2` via majority (n1 + n2), then heal n3 and verify catch-up
        nodes[0].raft_node().set_peer_blocked("n3", true)?;
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"RAFT.PROPOSE", b"SET", b"raft:k2", b"v2"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(nodes[2].storage().get_bytes(b"raft:k2")?, None);

        nodes[0].raft_node().set_peer_blocked("n3", false)?;
        let commit_idx = nodes[0].raft_node().replicate_to_peers()?;
        assert_eq!(commit_idx, 2);
        assert_eq!(
            nodes[2]
                .storage()
                .get_bytes(b"raft:k2")?
                .as_deref(),
            Some(&b"v2"[..])
        );

        // 2. 16,384-slot Cluster `-MOVED`, `-ASK`, and `CLUSTER MIGRATE`
        let key = b"order:{user42}:cart";
        let slot = key_hash_slot(key);
        let slot_str = slot.to_string();
        nodes[0].cluster_topology().set_enabled(true);
        nodes[1].cluster_topology().set_enabled(true);

        // Assign `slot` to Node 2 (`addrs[1]`) on Node 1 -> verify `-MOVED`
        send_cmd(
            &mut c0,
            &mut r0,
            &[b"CLUSTER", b"SETSLOT", slot_str.as_bytes(), b"NODE", addrs[1].as_bytes()],
        )?;
        let moved_reply = send_cmd(&mut c0, &mut r0, &[b"GET", key])?;
        match moved_reply {
            OwnedFrame::SimpleError(e) => {
                let s = String::from_utf8_lossy(&e);
                assert!(s.starts_with(&format!("MOVED {} {}", slot, addrs[1])));
            }
            other => return Err(EngineError::Protocol(format!("expected MOVED, got {other:?}"))),
        }

        // Reassign slot to SELF on Node 1, write key, migrate live key to Node 2
        send_cmd(
            &mut c0,
            &mut r0,
            &[b"CLUSTER", b"SETSLOT", slot_str.as_bytes(), b"NODE", b"SELF"],
        )?;
        send_cmd(&mut c0, &mut r0, &[b"SET", key, b"paid"])?;
        assert_eq!(
            send_cmd(
                &mut c0,
                &mut r0,
                &[b"CLUSTER", b"MIGRATE", addrs[1].as_bytes(), key]
            )?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            nodes[1].storage().get_bytes(key)?.as_deref(),
            Some(&b"paid"[..])
        );

        // 3. Hybrid Disk LSM-Tree (`LSM.PUT`, `LSM.FLUSH`, `LSM.DEL`, `LSM.COMPACT`, `LSM.GET`)
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.PUT", b"cold:1", b"payload_alpha"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.PUT", b"cold:2", b"payload_beta"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.FLUSH"])?,
            OwnedFrame::Integer(1)
        );
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.DEL", b"cold:1"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        let _ = send_cmd(&mut c0, &mut r0, &[b"LSM.FLUSH"])?;
        let _ = send_cmd(&mut c0, &mut r0, &[b"LSM.COMPACT"])?;
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.GET", b"cold:1"])?,
            OwnedFrame::Null
        );
        assert_eq!(
            send_cmd(&mut c0, &mut r0, &[b"LSM.GET", b"cold:2"])?,
            OwnedFrame::BulkString(b"payload_beta".to_vec())
        );

        drop(c0);
        for mut n in nodes {
            n.shutdown();
        }
        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_phase5_gorilla_ts_rbac_acl_slowlog_and_prometheus_http() -> EngineResult<()> {
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            worker_threads: 3,
            shard_count: 8,
            aof_path: None,
            snapshot_path: env::temp_dir().join("ferrum_p5_unused.snap"),
            ..ServerConfig::default()
        };
        let mut server = FerrumServer::start(cfg)?;
        let addr = server.local_addr().to_string();

        let mut c = TcpStream::connect(&addr)?;
        c.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut r = StreamReadBuffer::with_capacity(8192);

        // 1. Gorilla Time-Series + Downsampling Aggregation
        send_cmd(&mut c, &mut r, &[b"TS.ADD", b"temp:rack1", b"1000", b"20.0"])?;
        send_cmd(&mut c, &mut r, &[b"TS.ADD", b"temp:rack1", b"1500", b"30.0"])?;
        send_cmd(&mut c, &mut r, &[b"TS.ADD", b"temp:rack1", b"2200", b"40.0"])?;
        let range_agg = send_cmd(
            &mut c,
            &mut r,
            &[b"TS.RANGE", b"temp:rack1", b"1000", b"3000", b"AGG", b"avg", b"1000"],
        )?;
        match range_agg {
            OwnedFrame::Array(buckets) => assert_eq!(buckets.len(), 2),
            other => return Err(EngineError::Protocol(format!("unexpected TS.RANGE: {other:?}"))),
        }

        // 2. SlowLog threshold `0` captures commands
        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"CONFIG", b"SET", b"slowlog-log-slower-than", b"0"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        let _ = send_cmd(&mut c, &mut r, &[b"PING"])?;
        match send_cmd(&mut c, &mut r, &[b"SLOWLOG", b"LEN"])? {
            OwnedFrame::Integer(n) => assert!(n >= 1),
            other => return Err(EngineError::Protocol(format!("unexpected SLOWLOG LEN: {other:?}"))),
        }

        // 3. RBAC ACL user creation, AUTH, key-prefix & read-only enforcement
        assert_eq!(
            send_cmd(
                &mut c,
                &mut r,
                &[
                    b"ACL",
                    b"SETUSER",
                    b"reader",
                    b"on",
                    b">s3cr3t",
                    b"+@read",
                    b"~temp:*",
                ]
            )?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"AUTH", b"reader", b"s3cr3t"])?,
            OwnedFrame::SimpleString(b"OK".to_vec())
        );
        assert_eq!(
            send_cmd(&mut c, &mut r, &[b"ACL", b"WHOAMI"])?,
            OwnedFrame::BulkString(b"reader".to_vec())
        );
        // Write command denied (`NOPERM`)
        match send_cmd(&mut c, &mut r, &[b"SET", b"temp:rack1", b"hack"])? {
            OwnedFrame::SimpleError(e) => {
                assert!(String::from_utf8_lossy(&e).contains("NOPERM"));
            }
            other => return Err(EngineError::Protocol(format!("expected NOPERM, got {other:?}"))),
        }
        drop(c);

        // 4. Dual-Protocol Prometheus HTTP `/metrics` scrape on the exact same TCP port
        let mut http_sock = TcpStream::connect(&addr)?;
        http_sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        http_sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut raw_http = String::new();
        http_sock.read_to_string(&mut raw_http)?;
        assert!(raw_http.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(raw_http.contains("ferrum_commands_processed_total "));
        assert!(raw_http.contains("ferrum_raft_term "));
        drop(http_sock);

        server.shutdown();
        let _ = fs::remove_file(env::temp_dir().join("ferrum_p5_unused.snap"));
        Ok(())
    }
}
