//! Garry Autonomous Formal Verification & Axiom Engine - CLI Entrypoint & Bare-Metal Benchmarks.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - BOUNDED MEMORY - ZERO EXTERNAL CRATES - FAIL-CLOSED]

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use garry_core::interactive::{run_interactive_repl, InteractiveConfig};
use garry_core::metering::{MeterConfig, StepMeter};
use garry_core::plan::{NodeStatus, PlanGraph};
use garry_core::{
    ActionProposal, BoundedStorage, CheckpointMetadata, DeterministicEngine, EngineError,
    CHECKPOINT_SIZE,
};

pub struct BenchmarkResult {
    pub iterations: usize,
    pub mean_value: f64,
    pub target_value: f64,
    pub throughput_mb_s: Option<f64>,
    pub passed: bool,
}

fn bench_storage_action_handler(
    payload: &[u8],
    storage: &mut BoundedStorage,
) -> Result<(), EngineError> {
    storage.set(b"bench_key", payload)
}

fn create_full_16_node_dag() -> PlanGraph {
    let mut graph = PlanGraph::new();

    let n0 = graph.add_node("BENCH_ACTION", b"payload_0", &[]).unwrap();
    let n1 = graph.add_node("BENCH_ACTION", b"payload_1", &[n0]).unwrap();
    let n2 = graph.add_node("BENCH_ACTION", b"payload_2", &[n0]).unwrap();
    let n3 = graph.add_node("BENCH_ACTION", b"payload_3", &[n0]).unwrap();
    let n4 = graph.add_node("BENCH_ACTION", b"payload_4", &[n1, n2]).unwrap();
    let n5 = graph.add_node("BENCH_ACTION", b"payload_5", &[n2, n3]).unwrap();
    let n6 = graph.add_node("BENCH_ACTION", b"payload_6", &[n1, n3]).unwrap();
    let n7 = graph.add_node("BENCH_ACTION", b"payload_7", &[n4, n5]).unwrap();
    let n8 = graph.add_node("BENCH_ACTION", b"payload_8", &[n5, n6]).unwrap();
    let n9 = graph.add_node("BENCH_ACTION", b"payload_9", &[n4, n6]).unwrap();
    let n10 = graph.add_node("BENCH_ACTION", b"payload_10", &[n7, n8]).unwrap();
    let n11 = graph.add_node("BENCH_ACTION", b"payload_11", &[n8, n9]).unwrap();
    let n12 = graph
        .add_node("BENCH_ACTION", b"payload_12", &[n7, n9, n10, n11])
        .unwrap();
    let n13 = graph
        .add_node("BENCH_ACTION", b"payload_13", &[n10, n11])
        .unwrap();
    let n14 = graph
        .add_node("BENCH_ACTION", b"payload_14", &[n11, n12, n13])
        .unwrap();
    let _n15 = graph
        .add_node("BENCH_ACTION", b"payload_15", &[n12, n13, n14])
        .unwrap();

    graph.set_node_status(n0, NodeStatus::Succeeded).unwrap();
    graph.set_node_status(n1, NodeStatus::Succeeded).unwrap();
    graph.set_node_status(n2, NodeStatus::Succeeded).unwrap();
    graph.set_node_status(n3, NodeStatus::Succeeded).unwrap();

    graph
}

fn bench_plan_graph_resolve_readiness() -> BenchmarkResult {
    let template = create_full_16_node_dag();
    let iterations = match cfg!(debug_assertions) {
        true => 1_000,
        false => 10_000,
    };
    let target_ns = match cfg!(debug_assertions) {
        true => 50_000.0,
        false => 5_000.0,
    };

    let start = Instant::now();
    let mut idx = 0usize;
    while idx < iterations {
        let mut g = template.clone();
        let mut meter = StepMeter::new(MeterConfig::standard(100_000));
        let _ = black_box(g.resolve_readiness(&mut meter));
        idx += 1;
    }
    let elapsed = start.elapsed();
    let mean_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let passed = mean_ns <= target_ns;

    BenchmarkResult {
        iterations,
        mean_value: mean_ns,
        target_value: target_ns,
        throughput_mb_s: None,
        passed,
    }
}

fn bench_deterministic_engine_export_checkpoint() -> BenchmarkResult {
    let mut engine = DeterministicEngine::new(100);
    engine
        .register_action("BENCH_ACTION", bench_storage_action_handler)
        .unwrap();

    for i in 0..16 {
        let payload = format!("checkpoint_seed_payload_{:02}", i);
        let proposal = ActionProposal::new("BENCH_ACTION", payload.as_bytes())
            .unwrap()
            .validate(1)
            .unwrap();
        engine.trigger_planning().unwrap();
        engine.execute_proposal(proposal).unwrap();
    }

    let iterations = match cfg!(debug_assertions) {
        true => 500,
        false => 10_000,
    };
    let target_us = match cfg!(debug_assertions) {
        true => 500.0,
        false => 100.0,
    };

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = black_box(engine.export_checkpoint_array());
    }
    let elapsed = start.elapsed();
    let mean_us = (elapsed.as_nanos() as f64 / iterations as f64) / 1000.0;
    let throughput_mb_s = (CHECKPOINT_SIZE as f64 * iterations as f64)
        / elapsed.as_secs_f64().max(1e-9)
        / (1024.0 * 1024.0);
    let passed = mean_us <= target_us;

    BenchmarkResult {
        iterations,
        mean_value: mean_us,
        target_value: target_us,
        throughput_mb_s: Some(throughput_mb_s),
        passed,
    }
}

fn run_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing Garry Core Bare-Metal Benchmarks (Air-Gapped, Zero-Allocation)...");
    let readiness = bench_plan_graph_resolve_readiness();
    let export = bench_deterministic_engine_export_checkpoint();

    let r_status = match readiness.passed {
        true => "PASS",
        false => "FAIL",
    };
    let e_status = match export.passed {
        true => "PASS",
        false => "FAIL",
    };

    println!("+---------------------------------------------------+------------+---------------+--------------------+--------+");
    println!("| Benchmark Operation                               | Iterations | Mean Latency  | Target / Throughput| Status |");
    println!("+---------------------------------------------------+------------+---------------+--------------------+--------+");
    println!(
        "| PlanGraph::resolve_readiness (16-node DAG)        | {:>10} |   {:>8.2} ns | <= {:>7.2} ns      | {:<6} |",
        readiness.iterations, readiness.mean_value, readiness.target_value, r_status
    );
    println!(
        "| DeterministicEngine::export_checkpoint (7865 B)   | {:>10} |   {:>8.2} us | {:>7.2} MB/s       | {:<6} |",
        export.iterations,
        export.mean_value,
        export.throughput_mb_s.unwrap_or(0.0),
        e_status
    );
    println!("+---------------------------------------------------+------------+---------------+--------------------+--------+");

    Ok(())
}

fn cmd_inspect_checkpoint(path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path_str);
    let bytes = std::fs::read(path)?;
    match CheckpointMetadata::inspect(&bytes) {
        Ok(meta) => {
            println!("Checkpoint Integrity Verified (CRC-32: {:#010X})", meta.checksum);
            println!("  State: {:?} | Epoch: {} | Tick: {}", meta.state, meta.epoch, meta.tick);
            println!("  Storage Slots Used: {} / 16", meta.storage_slots_used);
            Ok(())
        }
        Err(e) => Err(format!("Invalid checkpoint: {}", e).into()),
    }
}

fn print_help() {
    println!("Garry Autonomous Formal Verification & Axiom Engine CLI");
    println!("Usage:");
    println!("  cargo run -- interactive              Launch interactive REPL (:swarm, :audit, :storage)");
    println!("  cargo run -- bench                    Execute bare-metal stack micro-benchmarks");
    println!("  cargo run -- inspect-checkpoint <p>   Inspect 7865-byte binary checkpoint seal");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("interactive");

    match cmd {
        "interactive" | "--interactive" => run_interactive_repl(InteractiveConfig::default()),
        "bench" | "--bench" => run_benchmarks(),
        "inspect-checkpoint" | "--inspect-checkpoint" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or(".garry/interactive.checkpoint");
            cmd_inspect_checkpoint(path)
        }
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        _ => run_interactive_repl(InteractiveConfig::default()),
    }
}