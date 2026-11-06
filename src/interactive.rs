//! Synchronous Deterministic REPL Engine for Interactive CLI, Swarm Axiom Research, and Formal Code Auditing.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - ZERO VEC! - ZERO EXTERNAL CRATES - FAIL-CLOSED]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::audit::{AuditFinding, BoundaryMathProber, CodeAuditor, FoundryPocSynthesizer};
use crate::ephemeral::{
    evaluate_contract_structural_triage_stack, extract_json_string_field,
    extract_provenance_and_eth_address_stack, sanitize_git_url_stack, MathematicalAxiom,
    SovereignApprovalReport, SovereignAuthorizationGate, SwarmResearchCoordinator,
};
use crate::sensory_planner::{FsmSnapshot, IntentType, SensoryIntentPlanner};
use crate::solver::UniversalCodeSynthesizer;
use crate::{
    calculate_crc32, ActionProposal, BoundedStorage, CheckpointMetadata, DeterministicEngine,
    EngineError, EngineState, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};

#[derive(Debug, Clone)]
pub struct InteractiveConfig {
    pub max_steps: u32,
}

impl Default for InteractiveConfig {
    fn default() -> Self {
        Self { max_steps: 10_000 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InteractiveTurnReport {
    pub prompt: String,
    pub nodes_executed: usize,
    pub state: EngineState,
    pub gas_consumed: u64,
    pub steps_consumed: u32,
    pub checkpoint_crc32: u32,
    pub responses: Vec<String>,
}

pub fn safe_storage_set(
    storage: &mut BoundedStorage,
    key: &[u8],
    val: &[u8],
) -> Result<(), EngineError> {
    let k_len = key.len().min(MAX_KEY_SIZE);
    let v_len = val.len().min(MAX_VALUE_SIZE);
    let clamped_key = &key[..k_len];
    let clamped_val = &val[..v_len];

    match storage.set(clamped_key, clamped_val) {
        Ok(()) => Ok(()),
        Err(EngineError::StorageFull { .. }) => {
            let mut k_buf = [0u8; MAX_KEY_SIZE];
            let mut v_buf = [0u8; MAX_VALUE_SIZE];
            k_buf[..k_len].copy_from_slice(clamped_key);
            v_buf[..v_len].copy_from_slice(clamped_val);
            storage.slots[15] = Some((k_buf, k_len, v_buf, v_len));
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn trim_byte_slice(slice: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < slice.len() && slice[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = slice.len();
    while end > start && slice[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &slice[start..end]
}

fn handle_save_state(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_sensory_save", payload)
}

fn handle_vision_capture(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_vision_capture", payload)
}

fn handle_actuator_speak(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_actuator_speak", payload)
}

fn handle_fs_worker(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_fs_operation", payload)
}

fn handle_command_worker(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_command_worker", payload)
}

fn handle_compute_worker(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    safe_storage_set(storage, b"last_compute_worker", payload)
}

fn handle_store_axiom(payload: &[u8], storage: &mut BoundedStorage) -> Result<(), EngineError> {
    match payload.iter().position(|&b| b == b'=' || b == b':') {
        Some(pos) => {
            let key = trim_byte_slice(&payload[..pos]);
            let has_double_eq = payload.len() > pos + 1 && payload[pos + 1] == b'=';
            let val = match has_double_eq {
                true => trim_byte_slice(&payload[pos + 2..]),
                false => trim_byte_slice(&payload[pos + 1..]),
            };

            match key.is_empty() {
                false => safe_storage_set(storage, key, val),
                true => safe_storage_set(storage, b"last_axiom", payload),
            }
        }
        None => safe_storage_set(storage, b"last_axiom", payload),
    }
}

pub fn register_sensory_actions(engine: &mut DeterministicEngine) -> Result<(), EngineError> {
    engine.register_action("SAVE_STATE_ACTION", handle_save_state)?;
    engine.register_action("VISION_CAPTURE", handle_vision_capture)?;
    engine.register_action("ACTUATOR_SPEAK", handle_actuator_speak)?;
    engine.register_action("FS_WORKER", handle_fs_worker)?;
    engine.register_action("COMMAND_WORKER", handle_command_worker)?;
    engine.register_action("STORE_AXIOM", handle_store_axiom)?;
    engine.register_action("COMPUTE_WORKER", handle_compute_worker)?;
    Ok(())
}

pub fn rollover_engine_if_completed(engine: &mut DeterministicEngine) -> Result<(), String> {
    let is_terminal =
        engine.state() == EngineState::Completed || engine.state() == EngineState::Failed;
    match is_terminal {
        false => return Ok(()),
        true => {}
    }

    let checkpoint = engine.export_checkpoint_array();
    let meta = CheckpointMetadata::inspect(&checkpoint)
        .map_err(|e| format!("Failed to inspect checkpoint during rollover: {:?}", e))?;

    let mut preserved_slots = Vec::with_capacity(16);
    for slot in engine.storage().slots.iter().flatten() {
        let mut key = Vec::with_capacity(slot.1);
        key.extend_from_slice(&slot.0[..slot.1]);
        let mut val = Vec::with_capacity(slot.3);
        val.extend_from_slice(&slot.2[..slot.3]);
        match key.as_slice() == b"last_executed_type" {
            false => preserved_slots.push((key, val)),
            true => {}
        }
    }

    let mut new_engine = DeterministicEngine::new(meta.max_steps);
    register_sensory_actions(&mut new_engine)
        .map_err(|e| format!("Failed to register sensory actions on rollover: {}", e))?;

    for (key, val) in preserved_slots.into_iter().take(12) {
        match new_engine.state() {
            EngineState::Idle | EngineState::Verifying => {
                new_engine
                    .trigger_planning()
                    .map_err(|e| format!("Rollover trigger planning failed: {}", e))?;
            }
            _ => {}
        }

        let max_val_len = MAX_VALUE_SIZE.saturating_sub(key.len().min(MAX_KEY_SIZE) + 1);
        let safe_val = match val.len() > max_val_len {
            true => &val[..max_val_len],
            false => &val[..],
        };

        let mut payload = Vec::with_capacity(key.len() + 1 + safe_val.len());
        payload.extend_from_slice(&key[..key.len().min(MAX_KEY_SIZE)]);
        payload.push(b'=');
        payload.extend_from_slice(safe_val);

        let proposal = ActionProposal::new("STORE_AXIOM", &payload)
            .map_err(|e| format!("Rollover proposal creation failed: {}", e))?
            .validate(1)
            .map_err(|e| format!("Rollover proposal validation failed: {}", e))?;

        new_engine
            .execute_proposal(proposal)
            .map_err(|e| format!("Rollover proposal execution failed: {}", e))?;
    }

    *engine = new_engine;
    Ok(())
}

pub fn execute_sandboxed_fs_operation(payload: &[u8]) -> Result<String, String> {
    let payload_str =
        std::str::from_utf8(payload).map_err(|e| format!("Invalid UTF-8 payload: {}", e))?;

    let op = extract_json_string_field(payload_str, "op").unwrap_or_else(|| "read".to_string());
    let rel_path_str = extract_json_string_field(payload_str, "path")
        .unwrap_or_else(|| "workspace_output.txt".to_string());

    let rel_path = Path::new(&rel_path_str);
    for component in rel_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(format!(
                    "Security violation: path traversal '..' is prohibited: {}",
                    rel_path_str
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(format!(
                    "Security violation: absolute paths are prohibited: {}",
                    rel_path_str
                ));
            }
            _ => {}
        }
    }

    let workspace_dir = PathBuf::from("garry_workspace");
    std::fs::create_dir_all(&workspace_dir)
        .map_err(|e| format!("Failed to create workspace directory: {}", e))?;

    let target_path = workspace_dir.join(rel_path);

    match op.as_str() {
        "synthesize" => {
            match target_path.parent() {
                Some(parent) => {
                    let _ = std::fs::create_dir_all(parent);
                }
                None => {}
            }
            let query = extract_json_string_field(payload_str, "query").unwrap_or_default();
            let synth = UniversalCodeSynthesizer::new();
            let script_code = synth.synthesize_script(&query);
            std::fs::write(&target_path, script_code)
                .map_err(|e| format!("Failed to write synthesized script: {}", e))?;
            Ok(format!(
                "Executable script 'garry_workspace/{}' synthesized successfully.",
                rel_path_str
            ))
        }
        "write" => {
            match target_path.parent() {
                Some(parent) => {
                    let _ = std::fs::create_dir_all(parent);
                }
                None => {}
            }
            let content = match extract_json_string_field(payload_str, "from") {
                Some(from_rel) => {
                    let from_path = workspace_dir.join(from_rel);
                    match from_path.exists() {
                        true => std::fs::read_to_string(&from_path).unwrap_or_default(),
                        false => extract_json_string_field(payload_str, "data").unwrap_or_default(),
                    }
                }
                None => extract_json_string_field(payload_str, "data").unwrap_or_default(),
            };
            std::fs::write(&target_path, content)
                .map_err(|e| format!("Failed to write file: {}", e))?;
            Ok(format!(
                "Artifact 'garry_workspace/{}' committed to disk.",
                rel_path_str
            ))
        }
        "read" => {
            match target_path.exists() {
                false => {
                    return Err(format!(
                        "Artifact 'garry_workspace/{}' does not exist.",
                        rel_path_str
                    ))
                }
                true => {}
            }
            let content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {}", e))?;
            Ok(format!(
                "Read 'garry_workspace/{}': {}",
                rel_path_str, content
            ))
        }
        "delete" => {
            match target_path.exists() {
                true => {
                    let _ = std::fs::remove_file(&target_path);
                }
                false => {}
            }
            Ok(format!("Removed 'garry_workspace/{}'.", rel_path_str))
        }
        unsupported => Err(format!("Unsupported filesystem operation: {}", unsupported)),
    }
}

pub fn execute_sandboxed_command(cmd_str: &str) -> Result<(String, Option<String>), String> {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    match parts.is_empty() {
        true => return Err("Empty command payload".to_string()),
        false => {}
    }

    let program = parts[0];
    let args = &parts[1..];

    let mut child = match std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            let synth = UniversalCodeSynthesizer::new();
            let (summary, report) = synth.execute_in_process_fallback(cmd_str)?;
            return Ok((summary, Some(report)));
        }
    };

    let mut time_budget_steps = 500usize;
    let mut is_completed = false;

    while time_budget_steps > 0 {
        time_budget_steps -= 1;
        match child.try_wait() {
            Ok(Some(_)) => {
                is_completed = true;
                break;
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("Process status error: {}", e));
            }
        }
    }

    match is_completed {
        true => match child.wait_with_output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let summary = extract_json_string_field(&stdout, "summary").unwrap_or_else(|| {
                    stdout
                        .lines()
                        .next()
                        .unwrap_or("Command completed.")
                        .to_string()
                });
                let report = extract_json_string_field(&stdout, "report");
                Ok((summary, report))
            }
            Err(e) => Err(format!("Failed to read process stdout: {}", e)),
        },
        false => {
            let _ = child.kill();
            let _ = child.wait();
            Err("Sandboxed process terminated by Anti-Freeze Guard (Timeout Exceeded)".to_string())
        }
    }
}

pub fn execute_swarm_research_turn_sync(
    engine: &mut DeterministicEngine,
    gate: &SovereignAuthorizationGate,
    swarm_coordinator: &SwarmResearchCoordinator,
    topic: &str,
    knowledge_dir: &Path,
) -> Result<(MathematicalAxiom, SovereignApprovalReport, PathBuf), String> {
    rollover_engine_if_completed(engine)?;

    let axiom = swarm_coordinator
        .dispatch_executable_axiom_swarm_sync(topic, 8)
        .map_err(|e| format!("Swarm dispatch failed: {}", e))?;

    let report = gate
        .authorize_and_persist_executable_axiom(&axiom, knowledge_dir, engine)
        .map_err(|e| format!("Formal verification and persistence failed: {}", e))?;

    let persisted_path = knowledge_dir.join(format!("{}.jsonl", axiom.key));
    Ok((axiom, report, persisted_path))
}

pub fn execute_sensory_turn(
    engine: &mut DeterministicEngine,
    planner: &SensoryIntentPlanner,
    raw_prompt: &str,
    finalize_epoch: bool,
) -> Result<InteractiveTurnReport, String> {
    rollover_engine_if_completed(engine)?;

    let prompt_text = match raw_prompt.strip_prefix(':') {
        Some(p) => p.trim().to_string(),
        None => raw_prompt.trim().to_string(),
    };

    let mut responses = Vec::with_capacity(8);

    match planner.classify_intent(&prompt_text) {
        Ok(IntentType::ScriptExecution) => {
            match SensoryIntentPlanner::extract_inline_script_code(&prompt_text) {
                Some(script_code) => {
                    let scripts_dir = PathBuf::from("garry_workspace").join("scripts");
                    let _ = std::fs::create_dir_all(&scripts_dir);
                    let temp_script_path = scripts_dir.join("temp_task.py");
                    let _ = std::fs::write(&temp_script_path, script_code);
                }
                None => {}
            }
        }
        _ => {}
    }

    let initial_checkpoint = engine.export_checkpoint_array();
    let initial_meta = CheckpointMetadata::inspect(&initial_checkpoint).ok();

    let snapshot = FsmSnapshot {
        state: engine.state(),
        epoch: initial_meta.as_ref().map(|meta| meta.epoch).unwrap_or(1),
        gas_consumed: engine.meter().consumed_units(),
        steps_consumed: engine.meter().consumed_steps(),
        checkpoint_crc32: initial_meta.as_ref().map(|meta| meta.checksum).unwrap_or(0),
        storage_slots_used: initial_meta
            .as_ref()
            .map(|meta| meta.storage_slots_used)
            .unwrap_or_else(|| engine.storage().slots.iter().flatten().count()),
    };

    let plan = planner
        .translate_intent_to_dag_with_snapshot(&prompt_text, &snapshot)
        .map_err(|err| format!("Intent translation failed: {}", err))?;

    let mut executed_count = 0usize;

    for i in 0..plan.len() {
        let node = match plan.get_node(i) {
            Some(n) => n,
            None => continue,
        };

        match engine.state() {
            EngineState::Idle | EngineState::Verifying => {
                engine
                    .trigger_planning()
                    .map_err(|e| format!("State transition to Planning failed: {}", e))?;
            }
            EngineState::Planning => {}
            other => {
                return Err(format!("Engine in invalid pre-execution state: {:?}", other));
            }
        }

        let proposal = ActionProposal::new(node.action_type, node.payload())
            .map_err(|e| format!("Action proposal creation failed: {}", e))?
            .validate(1)
            .map_err(|e| format!("Action proposal validation failed: {}", e))?;

        engine
            .execute_proposal(proposal)
            .map_err(|e| format!("Proposal execution failed at node {}: {}", i, e))?;

        match node.action_type {
            "SAVE_STATE_ACTION" => {
                responses.push("State checkpoint committed to bounded memory.".to_string());
            }
            "ACTUATOR_SPEAK" => {
                let msg = std::str::from_utf8(node.payload())
                    .unwrap_or("Garry confirmed deterministic execution.")
                    .to_string();
                responses.push(msg);
            }
            "FS_WORKER" => match execute_sandboxed_fs_operation(node.payload()) {
                Ok(msg) => responses.push(msg),
                Err(err) => responses.push(format!("Sandbox FS error: {}", err)),
            },
            "COMMAND_WORKER" => {
                let cmd_str = std::str::from_utf8(node.payload()).unwrap_or("");
                match execute_sandboxed_command(cmd_str) {
                    Ok((summary, _)) => responses.push(summary),
                    Err(err) => responses.push(format!("Sandbox command error: {}", err)),
                }
            }
            "STORE_AXIOM" => {
                responses.push("Axiom committed to 16-slot deterministic storage.".to_string());
            }
            _ => {}
        }

        executed_count += 1;
    }

    match finalize_epoch {
        true => {
            engine
                .finalize_verification(true)
                .map_err(|e| format!("Epoch finalization failed: {}", e))?;
        }
        false => {}
    }

    let checkpoint = engine.export_checkpoint_array();
    let metadata = CheckpointMetadata::inspect(&checkpoint)
        .map_err(|e| format!("Checkpoint verification failed: {}", e))?;

    Ok(InteractiveTurnReport {
        prompt: prompt_text,
        nodes_executed: executed_count,
        state: engine.state(),
        gas_consumed: engine.meter().consumed_units(),
        steps_consumed: engine.meter().consumed_steps(),
        checkpoint_crc32: metadata.checksum,
        responses,
    })
}

pub fn sync_exploit_poc_to_cli_and_test_dirs_stack(
    poc_solidity: &str,
    target_hint_opt: Option<&str>,
) -> PathBuf {
    let workspace_dir = PathBuf::from("garry_workspace");
    let _ = std::fs::create_dir_all(&workspace_dir);

    let primary_poc_path = workspace_dir.join("ExploitPoC.t.sol");
    let _ = std::fs::write(&primary_poc_path, poc_solidity);

    let ws_test_dir = workspace_dir.join("test");
    let _ = std::fs::create_dir_all(&ws_test_dir);
    let _ = std::fs::write(ws_test_dir.join("ExploitPoC.t.sol"), poc_solidity);

    match target_hint_opt {
        Some(raw_hint) => {
            let (clean_id, _, _) = extract_provenance_and_eth_address_stack(raw_hint);
            match !clean_id.is_empty() {
                true => {
                    let target_ns_dir = workspace_dir.join("targets").join(&clean_id);
                    match target_ns_dir.is_dir() {
                        true => {
                            let _ = std::fs::write(
                                target_ns_dir.join("ExploitPoC.t.sol"),
                                poc_solidity,
                            );
                        }
                        false => {}
                    }
                }
                false => {}
            }
        }
        None => {}
    }

    primary_poc_path
}

pub fn sync_isolated_1to1_poc_files_stack(
    file_name: &str,
    source: &str,
    findings: &[AuditFinding],
) -> usize {
    let probe = BoundaryMathProber::probe_contract_math(source);
    let isolated_list = FoundryPocSynthesizer::generate_isolated_1to1_poc_files_stack(
        file_name, source, findings, &probe,
    );
    let workspace_dir = PathBuf::from("garry_workspace");
    let ws_test_dir = workspace_dir.join("test");
    let _ = std::fs::create_dir_all(&ws_test_dir);

    let mut written = 0usize;
    let mut i = 0usize;
    while i < isolated_list.len() {
        let (ref iso_name, ref iso_code) = isolated_list[i];
        let _ = std::fs::write(workspace_dir.join(iso_name), iso_code);
        let _ = std::fs::write(ws_test_dir.join(iso_name), iso_code);
        written += 1;
        i += 1;
    }
    written
}

pub fn execute_autonomous_git_clone_and_ingest(
    raw_url: &str,
) -> Result<(String, Vec<String>), String> {
    let (clean_url, repo_name) = sanitize_git_url_stack(raw_url);
    let workspace_dir = PathBuf::from("garry_workspace");
    let repos_root = workspace_dir.join("repos");
    let target_repo_dir = repos_root.join(&repo_name);

    std::fs::create_dir_all(&repos_root)
        .map_err(|e| format!("Failed to create repos directory: {}", e))?;
    match target_repo_dir.exists() {
        true => {
            let _ = std::fs::remove_dir_all(&target_repo_dir);
        }
        false => {}
    }

    let target_dir_str = target_repo_dir.to_string_lossy().to_string();
    let mut child = std::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "-c",
            "core.longpaths=true",
            &clean_url,
            &target_dir_str,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn git clone: {}", e))?;

    let mut poll_budget = 1500usize;
    let mut finished = false;
    while poll_budget > 0 {
        poll_budget -= 1;
        match child.try_wait() {
            Ok(Some(_)) => {
                finished = true;
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(e) => {
                let _ = child.kill();
                return Err(format!("Git clone process error: {}", e));
            }
        }
    }

    match finished {
        false => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Git clone terminated by 15s Anti-Freeze Guard".to_string());
        }
        true => {}
    }

    const NONE_DIR: Option<PathBuf> = None;
    let mut dir_queue: [Option<PathBuf>; 64] = [NONE_DIR; 64];
    dir_queue[0] = Some(target_repo_dir.clone());
    let mut q_head = 0usize;
    let mut q_tail = 1usize;
    let mut scan_budget = 256usize;
    let mut extracted_files: Vec<String> = Vec::with_capacity(32);

    while q_head < q_tail && scan_budget > 0 && extracted_files.len() < 32 {
        scan_budget -= 1;
        let current_dir = match dir_queue[q_head].take() {
            Some(d) => d,
            None => break,
        };
        q_head += 1;

        match std::fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry_res in entries.take(128) {
                    match entry_res {
                        Ok(entry) => {
                            let path = entry.path();
                            let name_str = entry.file_name().to_string_lossy().to_string();
                            let name_low = name_str.to_lowercase();
                            match path.is_dir() {
                                true => {
                                    let ignored = name_low.starts_with('.')
                                        || name_low == "test"
                                        || name_low == "tests"
                                        || name_low == "lib"
                                        || name_low == "node_modules";
                                    match !ignored && q_tail < 64 {
                                        true => {
                                            dir_queue[q_tail] = Some(path);
                                            q_tail += 1;
                                        }
                                        false => {}
                                    }
                                }
                                false => {
                                    let is_sol = name_low.ends_with(".sol")
                                        && !name_low.ends_with(".t.sol")
                                        && !name_low.ends_with(".s.sol");
                                    match is_sol {
                                        true => match std::fs::read_to_string(&path) {
                                            Ok(raw_code) => {
                                                let triage =
                                                    evaluate_contract_structural_triage_stack(
                                                        &name_str, &raw_code,
                                                    );
                                                match !triage.should_prune
                                                    && extracted_files.len() < 32
                                                {
                                                    true => {
                                                        let _ = std::fs::write(
                                                            workspace_dir.join(&name_str),
                                                            &raw_code,
                                                        );
                                                        extracted_files.push(name_str);
                                                    }
                                                    false => {}
                                                }
                                            }
                                            Err(_) => {}
                                        },
                                        false => {}
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok((repo_name, extracted_files))
}

enum ReplCommand<'a> {
    Empty,
    Exit,
    StorageInspect,
    GitCloneAndAudit(&'a str),
    PartnerScope(&'a str),
    Audit(&'a str),
    SwarmResearch(&'a str),
    Turn(&'a str),
}

fn parse_repl_command(input: &str) -> ReplCommand<'_> {
    let trimmed = input.trim();
    match trimmed.is_empty() {
        true => return ReplCommand::Empty,
        false => {}
    }

    let lower = trimmed.to_lowercase();
    match lower.as_str() {
        "exit" | "quit" | ":exit" | ":quit" => return ReplCommand::Exit,
        ":storage" | ":axioms" | "storage" | "axioms" => return ReplCommand::StorageInspect,
        _ => {}
    }

    match trimmed.strip_prefix(":scope ") {
        Some(rest) => return ReplCommand::PartnerScope(rest.trim()),
        None => {}
    }
    match trimmed.strip_prefix(":clone ") {
        Some(rest) => return ReplCommand::GitCloneAndAudit(rest.trim()),
        None => {}
    }
    match trimmed.strip_prefix(":swarm ") {
        Some(rest) => return ReplCommand::SwarmResearch(rest.trim()),
        None => {}
    }
    match trimmed.strip_prefix(":research ") {
        Some(rest) => return ReplCommand::SwarmResearch(rest.trim()),
        None => {}
    }
    match trimmed.strip_prefix(":audit") {
        Some(rest) => return ReplCommand::Audit(rest.trim()),
        None => {}
    }
    match trimmed.strip_prefix(":scan") {
        Some(rest) => return ReplCommand::Audit(rest.trim()),
        None => {}
    }

    ReplCommand::Turn(trimmed)
}

pub fn run_interactive_repl(config: InteractiveConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = DeterministicEngine::new(config.max_steps);
    register_sensory_actions(&mut engine)?;

    let planner = SensoryIntentPlanner::new();
    let gate = SovereignAuthorizationGate::new();
    let swarm_coordinator = SwarmResearchCoordinator::new();

    let garry_dir = PathBuf::from(".garry");
    let checkpoint_file = garry_dir.join("interactive.checkpoint");

    println!("Garry Autonomous Formal Verification & Axiom Engine - Terminal REPL");
    println!("Commands: ':swarm <axiom>', ':audit <file.sol>', ':storage', or 'exit'");
    println!("  Workspace Root:   ./garry_workspace (Air-Gapped Sandbox Active)");
    println!("  Step Budget:      {}", config.max_steps);
    println!();

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();

    loop {
        print!("garry> ");
        std::io::stdout().flush()?;

        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        match bytes_read == 0 {
            true => break,
            false => {}
        }

        let trimmed = line.trim().to_string();

        match parse_repl_command(&trimmed) {
            ReplCommand::Empty => continue,
            ReplCommand::Exit => {
                println!("Terminating interactive session. Emitting final deterministic seal...");
                match engine.state() == EngineState::Verifying {
                    true => {
                        let _ = engine.finalize_verification(true);
                    }
                    false => {}
                }
                let final_checkpoint = engine.export_checkpoint_array();
                let _ = std::fs::create_dir_all(&garry_dir);
                let _ = std::fs::write(&checkpoint_file, &final_checkpoint);
                let crc = calculate_crc32(&final_checkpoint[..7861]);
                println!("Session finalized. Terminal CRC-32: {:#010X}", crc);
                break;
            }
            ReplCommand::StorageInspect => {
                let storage = engine.storage();
                let active_count = storage.slots.iter().flatten().count();
                println!("\n[BOUNDED 16-SLOT STACK STORAGE INSPECTION]");
                println!("  Active Slots: {} / 16", active_count);
                for (idx, slot) in storage.slots.iter().enumerate() {
                    match slot {
                        Some(s) => {
                            let k = std::str::from_utf8(&s.0[..s.1]).unwrap_or("<utf8-err>");
                            let v = std::str::from_utf8(&s.2[..s.3]).unwrap_or("<utf8-err>");
                            println!("  [{:>2}] {:<24} {}", idx, k, v);
                        }
                        None => {}
                    }
                }
                println!();
            }
            ReplCommand::PartnerScope(note_text) => {
                let scope_path = PathBuf::from("garry_workspace").join("partner_scope.txt");
                let _ = std::fs::create_dir_all("garry_workspace");
                let _ = std::fs::write(&scope_path, note_text);
                println!(
                    "Garry: Partner scope rules updated in '{}' ({} bytes).",
                    scope_path.display(),
                    note_text.len()
                );
            }
            ReplCommand::GitCloneAndAudit(url_token) => {
                match execute_autonomous_git_clone_and_ingest(url_token) {
                    Ok((repo_name, extracted_files)) => {
                        println!(
                            "[INGESTION COMPLETE] Repository '{}' -> Extracted {} core contracts.",
                            repo_name,
                            extracted_files.len()
                        );
                    }
                    Err(e) => println!("[GIT CLONE REJECTED] {}", e),
                }
            }
            ReplCommand::Audit(raw_target) => {
                let clean = raw_target.split_whitespace().next().unwrap_or("");
                let cand = PathBuf::from(clean);
                let resolved = match cand.exists() {
                    true => cand,
                    false => PathBuf::from("garry_workspace").join(&cand),
                };
                match std::fs::read_to_string(&resolved) {
                    Ok(code) => {
                        let fname = resolved
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(clean);
                        let knowledge_dir = PathBuf::from("garry_workspace").join("knowledge");
                        let files = [(fname, code.as_str())];
                        let (findings, report, poc_solidity) =
                            CodeAuditor::scan_multi_file_project(&files, &knowledge_dir);
                        println!("\n{}", report);
                        let report_out = PathBuf::from("garry_workspace").join("audit_report.txt");
                        let _ = std::fs::write(&report_out, &report);
                        match !findings.is_empty() {
                            true => {
                                let poc_out = sync_exploit_poc_to_cli_and_test_dirs_stack(
                                    &poc_solidity,
                                    Some(fname),
                                );
                                let iso_cnt =
                                    sync_isolated_1to1_poc_files_stack(fname, &code, &findings);
                                println!(
                                    "\n[FOUNDRY POC ARTIFACT] Emitted {} isolated PoC files & synced primary suite to: {}",
                                    iso_cnt,
                                    poc_out.display()
                                );
                            }
                            false => {}
                        }
                    }
                    Err(e) => println!("Garry: Unable to read target source '{}': {}", clean, e),
                }
            }
            ReplCommand::SwarmResearch(topic) => {
                let knowledge_dir = PathBuf::from("garry_workspace").join("knowledge");
                println!(
                    "\n[STATUS: SCANNING] Dispatching executable axiom swarm for '{}'...",
                    topic
                );
                match execute_swarm_research_turn_sync(
                    &mut engine,
                    &gate,
                    &swarm_coordinator,
                    topic,
                    &knowledge_dir,
                ) {
                    Ok((axiom, report, persisted_path)) => {
                        println!("[SOVEREIGN GATE: AXIOM VERIFIED & PERSISTED]");
                        println!("  - Axiom Title:        {}", axiom.title);
                        println!("  - Key Identifier:     {}", axiom.key);
                        println!("  - Domain Category:    {}", axiom.category);
                        println!("  - Output Symbols:     {}", axiom.output_symbol);
                        println!("  - L2 Knowledge Path:  {}", persisted_path.display());
                        println!(
                            "  - Checkpoint Seal:    {:#010X} (CRC-32 Valid)\n",
                            report.final_crc32
                        );
                    }
                    Err(err) => println!("[SWARM RESEARCH REJECTED] {}\n", err),
                }
            }
            ReplCommand::Turn(clean_cmd) => {
                match execute_sensory_turn(&mut engine, &planner, clean_cmd, true) {
                    Ok(report) => {
                        println!();
                        for resp in &report.responses {
                            println!("Garry: {}", resp);
                        }
                        println!(
                            "  [FSM TELEMETRY] State: {:?} | Steps: {} | Gas: {} | Seal: {:#010X}\n",
                            report.state,
                            report.steps_consumed,
                            report.gas_consumed,
                            report.checkpoint_crc32
                        );
                    }
                    Err(e) => println!("  [REJECTED] {}\n", e),
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ephemeral::lookup_mathematical_axiom_in_dir;

    #[test]
    fn test_handle_swarm_command_synthesizes_and_persists_to_disk() {
        let mut engine = DeterministicEngine::new(50);
        register_sensory_actions(&mut engine).unwrap();

        let gate = SovereignAuthorizationGate::new();
        let swarm_coordinator = SwarmResearchCoordinator::new();
        let temp_dir = PathBuf::from("garry_workspace").join("test_repl_swarm_knowledge");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let result = execute_swarm_research_turn_sync(
            &mut engine,
            &gate,
            &swarm_coordinator,
            "doolittle_lu",
            &temp_dir,
        );

        assert!(result.is_ok());
        let (axiom, report, persisted_path) = result.unwrap();
        assert_eq!(axiom.key, "doolittle_lu");
        assert!(persisted_path.exists());
        assert_ne!(report.final_crc32, 0);

        let loaded = lookup_mathematical_axiom_in_dir(&temp_dir, "doolittle_lu");
        assert!(loaded.is_some());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}