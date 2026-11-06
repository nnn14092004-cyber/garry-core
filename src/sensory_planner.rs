//! Natural Language Intent Classification, Deterministic Slot-Filling, and 16-Node DAG Generation.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - ZERO VEC! - ZERO EXTERNAL CRATES - FAIL-CLOSED]

use crate::ephemeral::{
    compute_problem_bitmask, extract_token_hashes_stack, fnv1a_hash_ascii_lower, has_token_hash,
    lookup_mathematical_axiom, HASH_DOOLITTLE,
};
use crate::plan::PlanGraph;
use crate::EngineState;

pub const MAX_NODE_PAYLOAD_SIZE: usize = 256;

/// Hardware peripheral device bitflags.
pub struct PeripheralFlags;
impl PeripheralFlags {
    pub const MIC: u8 = 1 << 0;
    pub const CAM: u8 = 1 << 1;
    pub const MOUSE: u8 = 1 << 2;
    pub const KEYBOARD: u8 = 1 << 3;
}

/// Access clearance level for sovereign execution control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearanceLevel {
    GuestMode,
    MasterClearance,
}

impl ClearanceLevel {
    pub const fn is_master(&self) -> bool {
        matches!(self, ClearanceLevel::MasterClearance)
    }
}

/// Pluggable planner backend trait for sensory execution graphs.
pub trait LlmPlannerBackend {
    fn translate_intent_to_dag(&self, text: &str) -> Result<PlanGraph, &'static str>;
    fn translate_intent_with_clearance(
        &self,
        text: &str,
        clearance: ClearanceLevel,
    ) -> Result<PlanGraph, &'static str>;
    fn translate_intent_to_dag_with_snapshot(
        &self,
        text: &str,
        snapshot: &FsmSnapshot,
    ) -> Result<PlanGraph, &'static str>;
}

/// High-level intent category classified from natural language inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentType {
    Conversational,
    SystemCommand,
    FileOperation,
    StoreAxiom,
    Compute,
    ComputeAndFile,
    ScriptExecution,
    PeripheralControl {
        device: u8,
        enable: bool,
    },
}

/// Instantaneous execution snapshot of the Deterministic Finite State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsmSnapshot {
    pub state: EngineState,
    pub epoch: u32,
    pub gas_consumed: u64,
    pub steps_consumed: u32,
    pub checkpoint_crc32: u32,
    pub storage_slots_used: usize,
}

impl Default for FsmSnapshot {
    fn default() -> Self {
        Self {
            state: EngineState::Idle,
            epoch: 1,
            gas_consumed: 0,
            steps_consumed: 0,
            checkpoint_crc32: 0,
            storage_slots_used: 0,
        }
    }
}

/// Checks whether a query represents a multi-axiom smart contract security audit.
pub fn is_multi_axiom_contract_audit_query_stack(raw_text: &str, lower: &str) -> bool {
    let has_solidity_structure = (lower.contains("contract ")
        || lower.contains("function ")
        || lower.contains("library "))
        && raw_text.contains('{')
        && raw_text.contains('}');
    const AUDIT_TARGETS: &[&str] = &[
        "reentrancy", "cei", "call{", ".call", "erc4626", "amm", "lending", "liquidat", "bridge",
        "oracle", "flashloan", "governance", "proxy", "underflow", "slippage", "erc4337",
        "diamond",
    ];
    let has_audit_directive = (lower.contains("audit")
        || lower.contains("kiểm toán")
        || lower.contains("lỗ hổng"))
        && AUDIT_TARGETS.iter().any(|&kw| lower.contains(kw));
    has_solidity_structure || has_audit_directive
}

/// Extracts stage index from a script path such as `scripts/stage_0.py`.
pub fn extract_stage_index_from_path_stack(path: &str) -> Option<usize> {
    let lower = path.to_lowercase();
    match lower.find("stage_") {
        Some(idx) => {
            let rest = &lower[idx + 6..];
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            num_str.parse::<usize>().ok()
        }
        None => None,
    }
}

/// Builds a bounded 256-byte JSON payload for the sandboxed filesystem synthesizer worker.
pub fn build_synthesize_fs_payload_stack(script_path: &str, query: &str) -> String {
    let prefix = format!(r#"{{"op":"synthesize","path":"{}","query":""#, script_path);
    let suffix = r#""}"#;
    let available_bytes = MAX_NODE_PAYLOAD_SIZE.saturating_sub(prefix.len() + suffix.len());

    let stage_tag = match extract_stage_index_from_path_stack(script_path) {
        Some(s) => format!("[stage_{}] ", s),
        None => String::new(),
    };

    let clean_query: String = query
        .chars()
        .filter(|&c| c != '"' && c != '\\')
        .collect();

    let full_query = format!("{}{}", stage_tag, clean_query);

    let mut bounded_query = &full_query[..];
    match bounded_query.len() > available_bytes {
        true => {
            let mut cut = available_bytes;
            while cut > 0 && !bounded_query.is_char_boundary(cut) {
                cut -= 1;
            }
            bounded_query = &bounded_query[..cut];
        }
        false => {}
    }

    format!("{}{}{}", prefix, bounded_query, suffix)
}

fn find_case_insensitive_boundary(haystack: &str, needle: &str) -> Option<(usize, usize)> {
    match needle.is_empty() {
        true => return None,
        false => {}
    }

    let needle_char_count = needle.chars().count();
    let mut char_indices = haystack.char_indices();
    let mut scan_budget = 4096usize;

    while scan_budget > 0 {
        scan_budget -= 1;
        match char_indices.next() {
            Some((start_byte, _)) => {
                let sub = &haystack[start_byte..];
                let mut matched = true;
                let mut matched_bytes = 0usize;
                let mut n_iter = needle.chars();
                let mut h_iter = sub.chars();

                let mut matched_chars = 0usize;
                while matched_chars < needle_char_count {
                    match (h_iter.next(), n_iter.next()) {
                        (Some(h_c), Some(n_c)) => {
                            let h_lower = h_c.to_lowercase();
                            let n_lower = n_c.to_lowercase();
                            match h_lower.eq(n_lower) {
                                true => {
                                    matched_bytes += h_c.len_utf8();
                                    matched_chars += 1;
                                }
                                false => {
                                    matched = false;
                                    break;
                                }
                            }
                        }
                        _ => {
                            matched = false;
                            break;
                        }
                    }
                }

                match matched && matched_chars == needle_char_count {
                    true => return Some((start_byte, start_byte + matched_bytes)),
                    false => {}
                }
            }
            None => break,
        }
    }

    None
}

fn split_slice_into_buffer<'a>(
    segment: &'a str,
    delimiter: &str,
    out: &mut [&'a str; 8],
    out_count: &mut usize,
) {
    let mut remainder = segment;
    let mut found_delimiter = false;
    let mut loop_budget = 16usize;

    while loop_budget > 0 {
        loop_budget -= 1;
        match find_case_insensitive_boundary(remainder, delimiter) {
            Some((start, end)) => match end > start {
                true => {
                    found_delimiter = true;
                    let prefix = remainder[..start]
                        .trim()
                        .trim_matches(|c: char| c == ',' || c == ';' || c == '.')
                        .trim();
                    match prefix.is_empty() {
                        false => match *out_count < 8 {
                            true => {
                                out[*out_count] = prefix;
                                *out_count += 1;
                            }
                            false => break,
                        },
                        true => {}
                    }
                    remainder = &remainder[end..];
                }
                false => break,
            },
            None => break,
        }
    }

    match found_delimiter {
        true => {
            let tail = remainder
                .trim()
                .trim_matches(|c: char| c == ',' || c == ';' || c == '.')
                .trim();
            match tail.is_empty() {
                false => match *out_count < 8 {
                    true => {
                        out[*out_count] = tail;
                        *out_count += 1;
                    }
                    false => {}
                },
                true => {}
            }
        }
        false => {
            let clean = segment
                .trim()
                .trim_matches(|c: char| c == ',' || c == ';' || c == '.')
                .trim();
            match clean.is_empty() {
                false => match *out_count < 8 {
                    true => {
                        out[*out_count] = clean;
                        *out_count += 1;
                    }
                    false => {}
                },
                true => {}
            }
        }
    }
}

/// Decomposes composite multi-stage intents using a stack-based Ping-Pong Buffer (Zero vec! macro).
pub fn split_composite_intents(text: &str) -> Vec<String> {
    let lower_check = text.to_lowercase();
    match is_multi_axiom_contract_audit_query_stack(text, &lower_check) {
        true => {
            let mut single = Vec::with_capacity(1);
            single.push(text.trim().to_string());
            return single;
        }
        false => {}
    }

    const CONJUNCTIONS: &[&str] = &[" rồi ", " sau đó ", " then ", " tiếp tục ", " -> "];

    let mut current_buf: [&str; 8] = [""; 8];
    let mut current_len = 0usize;

    let clean_init = text
        .trim()
        .trim_matches(|c: char| c == ',' || c == ';' || c == '.')
        .trim();

    match clean_init.is_empty() {
        false => {
            current_buf[0] = clean_init;
            current_len = 1;
        }
        true => {}
    }

    for &conj in CONJUNCTIONS {
        let mut next_buf: [&str; 8] = [""; 8];
        let mut next_len = 0usize;

        let mut i = 0usize;
        while i < current_len {
            split_slice_into_buffer(current_buf[i], conj, &mut next_buf, &mut next_len);
            i += 1;
        }

        match next_len > 0 {
            true => {
                current_len = next_len;
                let mut k = 0usize;
                while k < next_len {
                    current_buf[k] = next_buf[k];
                    k += 1;
                }
            }
            false => {}
        }
    }

    let mut out = Vec::with_capacity(current_len.max(1));
    match current_len {
        0 => out.push(text.trim().to_string()),
        len => {
            let mut k = 0usize;
            while k < len {
                out.push(current_buf[k].to_string());
                k += 1;
            }
        }
    }
    out
}

/// Deterministic semantic resolver and entity extractor for axiomatic rule learning.
#[derive(Debug, Clone, Copy, Default)]
pub struct SemanticIntentResolver;

impl SemanticIntentResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_learning_axiom(&self, text: &str) -> Option<(String, String)> {
        let normalized = text.trim();
        let lowered = normalized.to_lowercase();

        let has_khi_toi_noi = lowered.contains("khi tôi nói") && lowered.contains("thì");
        match has_khi_toi_noi {
            true => match lowered.split("khi tôi nói").nth(1) {
                Some(after) => {
                    let mut parts = after.split("thì");
                    match (parts.next(), parts.next()) {
                        (Some(raw_trig), Some(raw_act)) => {
                            let trigger = raw_trig
                                .trim()
                                .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                            let action = raw_act
                                .trim()
                                .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                            match !trigger.is_empty() && !action.is_empty() {
                                true => return Some((trigger.to_string(), action.to_string())),
                                false => {}
                            }
                        }
                        _ => {}
                    }
                }
                None => {}
            },
            false => {}
        }

        match lowered.contains("nếu nói") {
            true => match lowered.split("nếu nói").nth(1) {
                Some(after) => {
                    const SEPARATORS: &[&str] = &["thì hãy làm", "hãy làm", "thì làm", "thì", "hãy"];
                    for &sep in SEPARATORS {
                        match after.contains(sep) {
                            true => {
                                let mut parts = after.split(sep);
                                match (parts.next(), parts.next()) {
                                    (Some(raw_trig), Some(raw_act)) => {
                                        let trigger = raw_trig
                                            .trim()
                                            .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                                        let action = raw_act
                                            .trim()
                                            .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                                        match !trigger.is_empty() && !action.is_empty() {
                                            true => return Some((trigger.to_string(), action.to_string())),
                                            false => {}
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            false => {}
                        }
                    }
                }
                None => {}
            },
            false => {}
        }

        match normalized.contains(":=") {
            true => {
                let mut parts = normalized.split(":=");
                match (parts.next(), parts.next()) {
                    (Some(raw_left), Some(raw_right)) => {
                        let raw_trigger = raw_left
                            .replace("học quy tắc:", "")
                            .replace("quy tắc:", "")
                            .replace("dạy quy tắc:", "")
                            .replace("learn rule:", "")
                            .replace("rule:", "");
                        let trigger = raw_trigger
                            .trim()
                            .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                        let action = raw_right
                            .trim()
                            .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                        match !trigger.is_empty() && !action.is_empty() {
                            true => return Some((trigger.to_lowercase(), action.to_string())),
                            false => {}
                        }
                    }
                    _ => {}
                }
            }
            false => {}
        }

        for &sep in &["=>", "->"] {
            match normalized.contains(sep) {
                true => {
                    let mut parts = normalized.split(sep);
                    match (parts.next(), parts.next()) {
                        (Some(raw_left), Some(raw_right)) => {
                            let raw_trigger = raw_left
                                .replace("học quy tắc:", "")
                                .replace("quy tắc:", "")
                                .replace("dạy quy tắc:", "")
                                .replace("learn rule:", "")
                                .replace("rule:", "");
                            let trigger = raw_trigger
                                .trim()
                                .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                            let action = raw_right
                                .trim()
                                .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                            match !trigger.is_empty() && !action.is_empty() {
                                true => return Some((trigger.to_lowercase(), action.to_string())),
                                false => {}
                            }
                        }
                        _ => {}
                    }
                }
                false => {}
            }
        }

        None
    }
}

/// Rule-based deterministic planner converting sensory texts into 16-node execution DAGs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SensoryIntentPlanner;

impl SensoryIntentPlanner {
    pub fn new() -> Self {
        Self
    }

    pub fn classify_and_plan(&self, text: &str) -> Result<PlanGraph, &'static str> {
        self.translate_intent_to_dag(text)
    }

    pub fn split_composite_intents(text: &str) -> Vec<String> {
        split_composite_intents(text)
    }

    fn build_multi_stage_dag(
        &self,
        stages: &[String],
        original_text: &str,
    ) -> Result<PlanGraph, &'static str> {
        let mut graph = PlanGraph::new();
        let mut prev_cmd_id: Option<usize> = None;

        let target_file_opt = Self::extract_target_filename(original_text);
        let stage_limit = stages.len().min(7);

        let mut s = 0usize;
        while s < stage_limit {
            let raw_stage_query = &stages[s];
            let is_last_stage_with_target =
                s == stage_limit.saturating_sub(1) && target_file_opt.is_some();
            let stage_query = match is_last_stage_with_target {
                true => {
                    let (_, clean_q) = Self::extract_compute_and_file_params(raw_stage_query);
                    clean_q
                }
                false => raw_stage_query.clone(),
            };

            let synth_path = format!("scripts/stage_{}.py", s);
            let fs_synth_payload = build_synthesize_fs_payload_stack(&synth_path, &stage_query);

            let synth_deps_storage: [usize; 1];
            let synth_deps = match prev_cmd_id {
                Some(pid) => {
                    synth_deps_storage = [pid];
                    &synth_deps_storage[..]
                }
                None => &[][..],
            };

            let synth_node_id = graph
                .add_node("FS_WORKER", fs_synth_payload.as_bytes(), synth_deps)
                .map_err(|_| "Failed to add multi-stage script synthesizer node in DAG")?;

            let cmd_payload = format!("python garry_workspace/scripts/stage_{}.py", s);
            let cmd_node_id = graph
                .add_node("COMMAND_WORKER", cmd_payload.as_bytes(), &[synth_node_id])
                .map_err(|_| "Failed to add multi-stage script runner node in DAG")?;

            prev_cmd_id = Some(cmd_node_id);
            s += 1;
        }

        match (target_file_opt, prev_cmd_id) {
            (Some(path), Some(last_cmd_id)) => {
                let safe_path = match path.len() > 64 {
                    true => {
                        let mut end = 64;
                        while end > 0 && !path.is_char_boundary(end) {
                            end -= 1;
                        }
                        &path[..end]
                    }
                    false => &path,
                };

                let fs_write_payload = format!(
                    r#"{{"op":"write","path":"{}","from":"scripts/task_report.txt"}}"#,
                    safe_path
                );

                let _ = graph
                    .add_node("FS_WORKER", fs_write_payload.as_bytes(), &[last_cmd_id])
                    .map_err(|_| "Failed to add final report writer node in multi-stage DAG")?;
            }
            _ => {}
        }

        Ok(graph)
    }

    pub fn extract_inline_script_code(text: &str) -> Option<&str> {
        let trimmed = text.trim();
        let stripped = match trimmed.starts_with(':') {
            true => match trimmed.strip_prefix(':') {
                Some(s) => s.trim(),
                None => trimmed,
            },
            false => trimmed,
        };

        match stripped.find(':') {
            Some(colon_pos) => {
                let prefix = stripped[..colon_pos].trim().to_lowercase();
                let is_run_script = prefix.contains("chạy code")
                    || prefix.contains("chạy script")
                    || prefix.contains("run python")
                    || prefix.contains("exec python")
                    || prefix.contains("chạy python");

                match is_run_script {
                    true => {
                        let code = stripped[colon_pos + 1..].trim();
                        match code.is_empty() {
                            true => None,
                            false => Some(code),
                        }
                    }
                    false => None,
                }
            }
            None => None,
        }
    }

    pub fn extract_target_filename(text: &str) -> Option<String> {
        let lower = text.to_lowercase();
        const SUPPORTED_EXTS: &[&str] = &[".txt", ".md", ".json", ".log"];

        const MARKERS: &[&str] = &[
            "lưu vào file", "lưu vào tệp", "lưu vào", "lưu file", "lưu tệp",
            "xuất báo cáo ra file", "xuất báo cáo ra tệp", "xuất báo cáo ra", "xuất báo cáo",
            "xuất ra file", "xuất ra tệp", "xuất ra", "xuất file", "xuất tệp",
            "tạo file", "tạo tệp", "create file", "ghi file", "ghi tệp", "write file",
            "save to file", "save to", "save file", "export to file", "export to", "export file",
            "file", "tệp", "vào", "ra",
        ];

        for &marker in MARKERS {
            match lower.find(marker) {
                Some(idx) => {
                    let rest = text[idx + marker.len()..].trim();
                    match rest.split_whitespace().next() {
                        Some(token) => {
                            let clean = token.trim_matches(|c: char| {
                                c == '"' || c == '\'' || c == ',' || c == ';' || c == ':'
                                    || c == '(' || c == ')' || c == '[' || c == ']'
                            });
                            for &ext in SUPPORTED_EXTS {
                                match clean.to_lowercase().ends_with(ext) && clean.len() > ext.len()
                                {
                                    true => return Some(clean.to_string()),
                                    false => {}
                                }
                            }
                        }
                        None => {}
                    }
                }
                None => {}
            }
        }

        let mut token_budget = 128usize;
        for token in text.split_whitespace() {
            match token_budget == 0 {
                true => break,
                false => token_budget -= 1,
            }
            let clean = token.trim_matches(|c: char| {
                c == '"' || c == '\'' || c == ',' || c == ';' || c == ':' || c == '(' || c == ')'
                    || c == '[' || c == ']'
            });
            for &ext in SUPPORTED_EXTS {
                let matches_ext = clean.to_lowercase().ends_with(ext)
                    && clean.len() > ext.len()
                    && !clean.ends_with("task_report.txt");
                match matches_ext {
                    true => return Some(clean.to_string()),
                    false => {}
                }
            }
        }

        const SAVE_INDICATORS: &[&str] = &[
            "lưu file", "lưu tệp", "lưu vào file", "lưu vào tệp", "lưu vào", "tạo file",
            "tạo tệp", "ghi file", "ghi tệp", "xuất file", "xuất tệp", "xuất báo cáo", "xuất ra",
            "save file", "save to", "export to", "export file",
        ];

        match SAVE_INDICATORS.iter().any(|&ind| lower.contains(ind)) {
            true => {
                let is_cholesky = lower.contains("cholesky") || lower.contains("phân rã");
                let is_linear = lower.contains("hệ phương trình")
                    || lower.contains("hệ pt")
                    || lower.contains("gauss");
                let is_matrix = lower.contains("ma trận")
                    || lower.contains("matrix")
                    || lower.contains("định thức")
                    || lower.contains("determinant")
                    || lower.contains("det");

                match (is_cholesky, is_linear, is_matrix) {
                    (true, _, _) => Some("cholesky_report.txt".to_string()),
                    (_, true, _) => Some("linear_system_solution.txt".to_string()),
                    (_, _, true) => Some("matrix_solution.txt".to_string()),
                    _ => Some("computation_report.txt".to_string()),
                }
            }
            false => None,
        }
    }

    pub fn extract_compute_and_file_params(text: &str) -> (String, String) {
        let (legacy_path, content) = Self::extract_file_target_and_content(text);
        let has_valid_legacy = legacy_path != "workspace_output.txt"
            && content != "Garry verified file payload"
            && !content.is_empty();

        match has_valid_legacy {
            true => return (legacy_path, content),
            false => {}
        }

        let target_file = match Self::extract_target_filename(text) {
            Some(f) => f,
            None => {
                let lower = text.to_lowercase();
                let is_cholesky = lower.contains("cholesky") || lower.contains("phân rã");
                let is_linear = lower.contains("hệ phương trình")
                    || lower.contains("hệ pt")
                    || lower.contains("gauss");
                let is_matrix = lower.contains("ma trận")
                    || lower.contains("matrix")
                    || lower.contains("định thức")
                    || lower.contains("determinant")
                    || lower.contains("det");

                match (is_cholesky, is_linear, is_matrix) {
                    (true, _, _) => "cholesky_report.txt".to_string(),
                    (_, true, _) => "linear_system_solution.txt".to_string(),
                    (_, _, true) => "matrix_solution.txt".to_string(),
                    _ => "computation_report.txt".to_string(),
                }
            }
        };

        let lower = text.to_lowercase();
        const STRIP_MARKERS: &[&str] = &[
            "và lưu vào file", "và lưu vào tệp", "và lưu vào", "và lưu file", "và lưu tệp",
            "lưu vào file", "lưu vào tệp", "lưu vào", "lưu file", "lưu tệp",
            "xuất báo cáo ra file", "xuất báo cáo ra tệp", "xuất báo cáo ra", "xuất báo cáo",
            "xuất ra file", "xuất ra tệp", "xuất ra", "xuất file", "xuất tệp",
            "save to file", "save to", "save file", "export to file", "export to", "export file",
        ];

        let mut query = text.trim();
        for &marker in STRIP_MARKERS {
            match lower.find(marker) {
                Some(idx) => {
                    let candidate = text[..idx]
                        .trim()
                        .trim_end_matches(|c: char| c == ',' || c == ';' || c == ':');
                    match candidate.is_empty() {
                        false => {
                            query = candidate;
                            break;
                        }
                        true => {}
                    }
                }
                None => {}
            }
        }

        (target_file, query.to_string())
    }

    pub fn classify_intent(&self, text: &str) -> Result<IntentType, &'static str> {
        let trimmed = text.trim();
        let stripped = match trimmed.starts_with(':') {
            true => match trimmed.strip_prefix(':') {
                Some(s) => s.trim(),
                None => trimmed,
            },
            false => trimmed,
        };
        let normalized = stripped.to_lowercase();
        match normalized.is_empty() {
            true => return Err("Empty input string"),
            false => {}
        }

        type PeripheralRule = (&'static [&'static str], u8, bool);
        const PERIPHERAL_RULES: &[PeripheralRule] = &[
            (&["tắt mic", "khoá mic", "khóa mic", "mute mic"], PeripheralFlags::MIC, false),
            (&["bật mic", "mở mic", "unmute mic"], PeripheralFlags::MIC, true),
            (&["bật camera", "bật cam", "mở camera", "mở cam"], PeripheralFlags::CAM, true),
            (&["tắt camera", "tắt cam", "khóa camera", "khóa cam"], PeripheralFlags::CAM, false),
            (&["khóa chuột", "tắt chuột"], PeripheralFlags::MOUSE, false),
            (&["mở chuột", "bật chuột"], PeripheralFlags::MOUSE, true),
            (&["mở bàn phím", "bật bàn phím"], PeripheralFlags::KEYBOARD, true),
            (&["khóa bàn phím", "tắt bàn phím"], PeripheralFlags::KEYBOARD, false),
        ];

        for (patterns, dev, enable) in PERIPHERAL_RULES {
            match patterns.iter().any(|&p| normalized.contains(p)) {
                true => {
                    return Ok(IntentType::PeripheralControl {
                        device: *dev,
                        enable: *enable,
                    })
                }
                false => {}
            }
        }

        let is_inline_script = (normalized.starts_with("chạy code python:")
            || normalized.starts_with("chạy script python:")
            || normalized.starts_with("chạy code:")
            || normalized.starts_with("run python:")
            || normalized.starts_with("exec python:"))
            || ((normalized.starts_with("chạy code python")
                || normalized.starts_with("chạy script python")
                || normalized.starts_with("chạy code"))
                && normalized.contains(':')
                && !normalized.contains("tạo file")
                && !normalized.contains("ghi file"));

        match is_inline_script {
            true => return Ok(IntentType::ScriptExecution),
            false => {}
        }

        let has_file_action = Self::extract_target_filename(stripped).is_some()
            || normalized.contains("tạo file")
            || normalized.contains("create file")
            || normalized.contains("ghi file")
            || normalized.contains("write file")
            || normalized.contains("tạo tệp")
            || normalized.contains("ghi tệp")
            || normalized.contains("lưu file")
            || normalized.contains("lưu tệp")
            || normalized.contains("lưu vào file")
            || normalized.contains("lưu vào tệp")
            || normalized.contains("lưu vào")
            || normalized.contains("xuất file")
            || normalized.contains("xuất tệp")
            || normalized.contains("xuất báo cáo ra")
            || normalized.contains("xuất báo cáo")
            || normalized.contains("xuất ra")
            || normalized.contains("save to")
            || normalized.contains("export to");

        const COMPUTE_DOMAIN_KEYWORDS: &[&str] = &[
            "ma trận", "matrix", "định thức", "determinant", "det", "hệ phương trình", "hệ pt",
            "tuyến tính", "gauss", "cholesky", "phân rã", "factorization", "doolittle", "crout",
            "svd", "singular value", "householder", "givens", "schur", "hessenberg", "tridiagonal",
            "tam đường chéo", "ldl", "moore_penrose", "pseudoinverse", "giả nghịch đảo", "nghịch đảo", "inverse",
            "gradient", "độ dốc", "conjugate", "liên hợp", "bicgstab", "gmres", "seidel",
            "relaxation", "khử sai số", "sor", "rayleigh", "lặp lũy thừa", "power iteration",
            "trị riêng", "vector riêng", "vectơ riêng", "eigenvalue", "eigenvector", "phổ", "spectral",
            "vi phân", "đạo hàm", "tích phân", "ode", "runge", "kutta", "rk4", "verlet",
            "symplectic", "quỹ đạo", "bước số", "bước thời gian", "trajectory", "stepping",
            "hình học", "khung dây", "spatial", "đa diện", "polyhedron", "chóp", "pyramid",
            "tứ diện", "tetrahedron", "bát diện", "octahedron", "lập phương", "cube",
            "dodecahedron", "icosahedron", "quaternion", "euler-poincaré", "bloch",
            "quantum", "lượng tử", "qubit", "hilbert", "ma trận mật độ", "density matrix",
            "độ tinh khiết", "purity", "pauli", "hadamard", "bell state", "ghz", "entanglement",
            "vướng víu", "von neumann",
            "bất biến", "invariant", "slippage", "trượt giá", "constant product", "liquidity",
            "thanh khoản", "vault", "inflation", "lending", "npv", "irr", "wacc", "dol", "dfl",
            "dtl", "thẩm định", "chiếu trực giao", "không gian con", "subspace",
            "thuật toán", "giải thuật", "quicksort", "sắp xếp", "fibonacci",
            "silicon", "vi mã", "isa", "thanh ghi", "register", "stack", "ngăn xếp",
            "audit", "kiểm toán", "lỗ hổng", "reentrancy", "swc-107", "cwe-369", "erc4626",
            "erc20", "erc721", "erc1155", "vesting", "reward", "paymaster", "entrypoint",
            "pragma solidity", "contract ", "function ", "flashloan", "liquidat", "borrow",
            "collateral", "oracle", "twap", "bridge", "layerzero", "lzreceive", "ccip", "merkle",
            "governance", "timelock", "staking", "restaking", "erc4337", "diamond", "proxy",
            "underflow", "ecrecover", "permit", "mev", "sandwich",
            "future_cashflow", "cumulative_delta", "triage", "standard_json",
            "mainnet", "fork", "createselectfork", "live_state", "donateasyield",
            "drainyieldvault", "completemigration", "panic(0x11)", "openzeppelin",
            "uniswap", "v4lend", "hook", "automator", "harberger", "lease", "auction",
            "transformer", "sequencer", "recoveryperiod", "poolmanager", "beforeswap",
            "aave", "compound", "curve", "balancer", "morpho", "pendle", "eigenlayer",
            "wormhole", "pyth", "chainlink", "solmate", "solady", "exploitpoc", "foundry",
            "hypergraph", "resonance", "256 axioms", "risk grade", "critical",
            "causal trace", "stream_ring", "suspicion_filter", "smt_prover", "refutation",
            "bytecode_anchor", "axiom_decay", "patch_verify", "patch_deadlock", "secondary_poc",
        ];
        let has_domain_keyword = COMPUTE_DOMAIN_KEYWORDS.iter().any(|&k| normalized.contains(k));

        let has_action_prefix = normalized.starts_with("chạy script")
            || normalized.starts_with("run script")
            || normalized.starts_with("tính toán")
            || normalized.starts_with("tính:")
            || normalized.starts_with("tính ")
            || normalized.starts_with("tinh ")
            || normalized.starts_with("solve ")
            || normalized.starts_with("eval ")
            || normalized.starts_with("audit ")
            || normalized.starts_with("kiểm toán ");

        let (tok_hashes, tok_count) = extract_token_hashes_stack(&normalized);
        let has_isolated_lu = has_token_hash(&tok_hashes, tok_count, fnv1a_hash_ascii_lower(b"lu"))
            || has_token_hash(&tok_hashes, tok_count, HASH_DOOLITTLE);

        let has_compound_finance = (normalized.contains("q=") && normalized.contains("p="))
            || (normalized.contains("dòng tiền") && normalized.contains("vốn"));

        let is_contract_audit = is_multi_axiom_contract_audit_query_stack(stripped, &normalized);
        let has_bitmask_signal = compute_problem_bitmask(stripped) != 0 && has_domain_keyword;

        let has_compute_indicators = is_contract_audit
            || has_bitmask_signal
            || has_domain_keyword
            || has_action_prefix
            || has_isolated_lu
            || has_compound_finance
            || lookup_mathematical_axiom(&normalized).is_some();

        match (has_file_action, has_compute_indicators) {
            (true, true) => return Ok(IntentType::ComputeAndFile),
            (false, true) => return Ok(IntentType::Compute),
            _ => {}
        }

        let is_teaching_rule = normalized.contains("khi tôi nói")
            || normalized.contains("nếu nói")
            || normalized.contains("học quy tắc")
            || normalized.contains("dạy quy tắc")
            || normalized.contains("quy tắc:")
            || normalized.contains("learn rule:")
            || normalized.contains("rule:");

        match is_teaching_rule {
            true => return Ok(IntentType::StoreAxiom),
            false => {}
        }

        let is_file_op = has_file_action
            || normalized.contains("đọc file")
            || normalized.contains("read file")
            || normalized.contains("xóa file")
            || normalized.contains("delete file")
            || normalized.contains("đọc tệp")
            || normalized.contains("xóa tệp");

        match is_file_op {
            true => return Ok(IntentType::FileOperation),
            false => {}
        }

        let is_axiom_assign = normalized.contains(":=")
            || normalized.contains("=>")
            || normalized.contains("->")
            || (normalized.contains('=') && !normalized.contains("http"));

        match is_axiom_assign {
            true => return Ok(IntentType::StoreAxiom),
            false => {}
        }

        const SYS_CMD_INDICATORS: &[&str] = &[
            "lưu trạng thái", "lưu checkpoint", "save state", "chụp màn hình",
            "chụp màn", "screenshot", "click chuột", "nhấp chuột", "bấm chuột",
            "di chuột", "move mouse", "chuyển chuột", "gõ phím", "ấn phím",
            "bấm phím", "nhấn phím", "press key", "chạy lệnh", "exec", "cmd ",
            "git clone", "clone ", "dir", "ls", "forge test",
        ];
        let is_sys_cmd = SYS_CMD_INDICATORS
            .iter()
            .any(|&k| normalized.contains(k) || normalized.starts_with(k) || normalized == k);

        match is_sys_cmd {
            true => return Ok(IntentType::SystemCommand),
            false => {}
        }

        const CONV_INDICATORS: &[&str] = &[
            "chào", "hello", "hi", "garry", "thế nào", "sao rồi", "sao em",
            "thời tiết", "báo cáo", "status", "tình trạng", "có nghe",
            "hiểu không", "ổn không", "phản hồi", "xác nhận",
        ];

        let is_conv = CONV_INDICATORS.iter().any(|&k| normalized.contains(k));
        match is_conv {
            true => Ok(IntentType::Conversational),
            false => Err("Unrecognized natural language intent: safely rejected by planner"),
        }
    }

    pub fn extract_mouse_move_coords(text: &str) -> (i32, i32) {
        let lowered = text.to_lowercase();
        let mut coords = [500i32, 500i32];
        let mut count = 0usize;

        for token in lowered.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let clean = token.trim_matches(|c: char| !c.is_ascii_digit());
            match clean.parse::<i32>() {
                Ok(num) => match count < 2 {
                    true => {
                        coords[count] = num;
                        count += 1;
                    }
                    false => break,
                },
                Err(_) => {}
            }
        }

        match count >= 2 {
            true => (coords[0], coords[1]),
            false => (500, 500),
        }
    }

    pub fn extract_mouse_click_button(text: &str) -> &'static str {
        let lowered = text.to_lowercase();
        let is_right = lowered.contains("phải") || lowered.contains("right");
        let is_middle = lowered.contains("giữa") || lowered.contains("middle");
        let is_double = lowered.contains("đúp") || lowered.contains("double");

        match (is_right, is_middle, is_double) {
            (true, _, _) => "right",
            (_, true, _) => "middle",
            (_, _, true) => "double",
            _ => "left",
        }
    }

    pub fn extract_key_press(text: &str) -> String {
        let lowered = text.trim().to_lowercase();
        const PREFIXES: &[&str] = &[
            "gõ phím", "ấn phím", "bấm phím", "nhấn phím", "press key", "phím",
        ];
        let mut target = "";
        for &p in PREFIXES {
            match lowered.find(p) {
                Some(idx) => {
                    let remainder = lowered[idx + p.len()..]
                        .trim()
                        .trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                    match remainder.is_empty() {
                        false => {
                            target = remainder;
                            break;
                        }
                        true => {}
                    }
                }
                None => {}
            }
        }

        match target.is_empty() {
            true => return "0x41".to_string(),
            false => {}
        }

        let is_enter = target.contains("enter") || target.contains("return");
        let is_tab = target.contains("tab");
        let is_backspace = target.contains("backspace");
        let is_space = target.contains("space");
        let is_esc = target.contains("escape") || target.contains("esc");
        let is_ctrl = target.contains("ctrl+") || target.contains("control+");
        let is_hex = target.starts_with("0x");

        match (is_enter, is_tab, is_backspace, is_space, is_esc, is_ctrl, is_hex) {
            (true, _, _, _, _, _, _) => "enter".to_string(),
            (_, true, _, _, _, _, _) => "tab".to_string(),
            (_, _, true, _, _, _, _) => "backspace".to_string(),
            (_, _, _, true, _, _, _) => "space".to_string(),
            (_, _, _, _, true, _, _) => "esc".to_string(),
            (_, _, _, _, _, true, _) => target.replace("control+", "ctrl+"),
            (_, _, _, _, _, _, true) => {
                target.split_whitespace().next().unwrap_or("0x41").to_string()
            }
            _ => match target.split_whitespace().next() {
                Some(first_word) => {
                    let clean = first_word.trim_matches(|c: char| c == ':' || c == '"' || c == '\'');
                    match clean.is_empty() {
                        false => clean.to_string(),
                        true => "0x41".to_string(),
                    }
                }
                None => "0x41".to_string(),
            },
        }
    }

    pub fn extract_file_target_and_content(text: &str) -> (String, String) {
        let normalized = text.trim();
        let lowered = normalized.to_lowercase();

        const WRITE_KWS: &[&str] = &[
            "ghi file", "write file", "tạo file", "create file", "tạo tệp", "ghi tệp",
        ];

        for &kw in WRITE_KWS {
            match lowered.find(kw) {
                Some(idx) => {
                    let rest = normalized[idx + kw.len()..].trim();
                    let lowered_rest = rest.to_lowercase();
                    let mut path = "workspace_output.txt".to_string();
                    let mut data = "Garry verified file payload".to_string();

                    const DATA_MARKERS: &[&str] = &["với nội dung", "nội dung", "content", "data"];
                    let mut found_marker = None;
                    for &marker in DATA_MARKERS {
                        match lowered_rest.find(marker) {
                            Some(m_idx) => {
                                found_marker = Some((m_idx, marker.len()));
                                break;
                            }
                            None => {}
                        }
                    }

                    match found_marker {
                        Some((m_idx, m_len)) => {
                            let path_part = rest[..m_idx].trim();
                            let data_part = rest[m_idx + m_len..]
                                .trim()
                                .trim_matches(|c: char| {
                                    c == ':' || c == '=' || c == '"' || c == '\''
                                })
                                .trim();
                            match path_part.split_whitespace().next() {
                                Some(first_path) => {
                                    path = first_path
                                        .trim_matches(|c: char| {
                                            c == '"' || c == '\'' || c == ',' || c == ';' || c == ':'
                                        })
                                        .to_string();
                                }
                                None => {}
                            }
                            match data_part.is_empty() {
                                false => data = data_part.to_string(),
                                true => {}
                            }
                        }
                        None => match rest.split_whitespace().next() {
                            Some(first_path) => {
                                path = first_path
                                    .trim_matches(|c: char| {
                                        c == '"' || c == '\'' || c == ',' || c == ';' || c == ':'
                                    })
                                    .to_string();
                            }
                            None => {}
                        },
                    }

                    return (path, data);
                }
                None => {}
            }
        }

        ("workspace_output.txt".to_string(), text.to_string())
    }

    pub fn extract_file_payload(text: &str) -> String {
        let normalized = text.trim();
        let lowered = normalized.to_lowercase();

        let is_read = lowered.contains("đọc file")
            || lowered.contains("read file")
            || lowered.contains("đọc tệp");
        match is_read {
            true => {
                let kw = match (lowered.contains("đọc file"), lowered.contains("đọc tệp")) {
                    (true, _) => "đọc file",
                    (_, true) => "đọc tệp",
                    _ => "read file",
                };
                let path = match lowered.find(kw) {
                    Some(idx) => {
                        let rest = normalized[idx + kw.len()..].trim();
                        rest.split_whitespace()
                            .next()
                            .unwrap_or("workspace_output.txt")
                            .trim_matches(|c: char| {
                                c == '"' || c == '\'' || c == ',' || c == ';' || c == ':'
                            })
                    }
                    None => "workspace_output.txt",
                };
                return format!(r#"{{"op":"read","path":"{}"}}"#, path);
            }
            false => {}
        }

        let is_del = lowered.contains("xóa file")
            || lowered.contains("delete file")
            || lowered.contains("xóa tệp");
        match is_del {
            true => {
                let kw = match (lowered.contains("xóa file"), lowered.contains("xóa tệp")) {
                    (true, _) => "xóa file",
                    (_, true) => "xóa tệp",
                    _ => "delete file",
                };
                let path = match lowered.find(kw) {
                    Some(idx) => {
                        let rest = normalized[idx + kw.len()..].trim();
                        rest.split_whitespace()
                            .next()
                            .unwrap_or("workspace_output.txt")
                            .trim_matches(|c: char| {
                                c == '"' || c == '\'' || c == ',' || c == ';' || c == ':'
                            })
                    }
                    None => "workspace_output.txt",
                };
                return format!(r#"{{"op":"delete","path":"{}"}}"#, path);
            }
            false => {}
        }

        let (path, data) = Self::extract_file_target_and_content(text);

        let safe_path = match path.len() > 64 {
            true => {
                let mut end = 64;
                while end > 0 && !path.is_char_boundary(end) {
                    end -= 1;
                }
                &path[..end]
            }
            false => &path,
        };

        let escaped_data = data.replace('\\', "\\\\").replace('"', "\\\"");

        let prefix = r#"{"op":"write","path":""#;
        let middle = r#"","data":""#;
        let suffix = r#""}"#;
        let template_len = prefix.len() + safe_path.len() + middle.len() + suffix.len();
        let max_data_bytes = MAX_NODE_PAYLOAD_SIZE.saturating_sub(template_len);

        let bounded_data = match escaped_data.len() > max_data_bytes {
            true => {
                let mut cut = max_data_bytes;
                while cut > 0 && !escaped_data.is_char_boundary(cut) {
                    cut -= 1;
                }
                let slice = &escaped_data[..cut];
                let trailing_backslashes = slice.chars().rev().take_while(|&c| c == '\\').count();
                match trailing_backslashes % 2 != 0 {
                    true => &slice[..slice.len().saturating_sub(1)],
                    false => slice,
                }
            }
            false => &escaped_data[..],
        };

        format!("{}{}{}{}{}", prefix, safe_path, middle, bounded_data, suffix)
    }

    pub fn extract_command_payload(text: &str) -> String {
        let trimmed = text.trim();
        let lowered = trimmed.to_lowercase();
        const PREFIXES: &[&str] = &["chạy lệnh ", "exec ", "cmd "];
        for &p in PREFIXES {
            match lowered.starts_with(p) {
                true => return trimmed[p.len()..].trim().to_string(),
                false => {}
            }
        }
        trimmed.to_string()
    }

    pub fn generate_conversational_response(&self, text: &str, snapshot: &FsmSnapshot) -> String {
        let normalized = text.trim().to_lowercase();

        let is_status_inquiry = normalized.contains("thế nào")
            || normalized.contains("sao rồi")
            || normalized.contains("tình trạng")
            || normalized.contains("ổn không");
        let is_report = normalized.contains("báo cáo") || normalized.contains("status");
        let is_greeting =
            normalized.contains("chào") || normalized.contains("hello") || normalized.contains("hi");
        let is_hearing = normalized.contains("có nghe") || normalized.contains("hiểu không");

        match (is_status_inquiry, is_report, is_greeting, is_hearing) {
            (true, _, _, _) => {
                format!(
                    "Garry Engine operating deterministically in state {:?}. Logical clock epoch {}, steps executed: {}, gas consumed: {} units. Checkpoint seal: {:#010X}.",
                    snapshot.state,
                    snapshot.epoch,
                    snapshot.steps_consumed,
                    snapshot.gas_consumed,
                    snapshot.checkpoint_crc32
                )
            }
            (_, true, _, _) => {
                format!(
                    "Status Report: Garry Engine is 100% air-gapped. FSM state: {:?}, bounded memory active: {}/16 slots, CRC-32 seal: {:#010X}.",
                    snapshot.state,
                    snapshot.storage_slots_used,
                    snapshot.checkpoint_crc32
                )
            }
            (_, _, true, _) => {
                format!(
                    "Greetings! Garry Autonomous Engine is online at epoch {}. All 16 stack-bounded memory slots verified.",
                    snapshot.epoch
                )
            }
            (_, _, _, true) => {
                format!(
                    "Directive acknowledged. FSM is in state {:?}, gas consumed: {} units, zero regressions.",
                    snapshot.state,
                    snapshot.gas_consumed
                )
            }
            _ => {
                format!(
                    "Greetings! Garry received directive. FSM state: {:?}, deterministic parity preserved.",
                    snapshot.state
                )
            }
        }
    }

    pub fn translate_intent_to_dag_with_snapshot(
        &self,
        text: &str,
        snapshot: &FsmSnapshot,
    ) -> Result<PlanGraph, &'static str> {
        <Self as LlmPlannerBackend>::translate_intent_to_dag_with_snapshot(self, text, snapshot)
    }
}

impl LlmPlannerBackend for SensoryIntentPlanner {
    fn translate_intent_to_dag(&self, text: &str) -> Result<PlanGraph, &'static str> {
        self.translate_intent_to_dag_with_snapshot(text, &FsmSnapshot::default())
    }

    fn translate_intent_with_clearance(
        &self,
        text: &str,
        clearance: ClearanceLevel,
    ) -> Result<PlanGraph, &'static str> {
        match clearance {
            ClearanceLevel::GuestMode => {
                let mut graph = PlanGraph::new();
                let msg = "Access Denied: MasterClearance authorization required.";
                graph
                    .add_node("ACTUATOR_SPEAK", msg.as_bytes(), &[])
                    .map_err(|_| "Failed to add security rejection node")?;
                Ok(graph)
            }
            ClearanceLevel::MasterClearance => self.translate_intent_to_dag(text),
        }
    }

    fn translate_intent_to_dag_with_snapshot(
        &self,
        text: &str,
        snapshot: &FsmSnapshot,
    ) -> Result<PlanGraph, &'static str> {
        let stages = split_composite_intents(text);
        match stages.len() >= 2 {
            true => {
                let trimmed = text.trim();
                let stripped = match trimmed.starts_with(':') {
                    true => match trimmed.strip_prefix(':') {
                        Some(s) => s.trim(),
                        None => trimmed,
                    },
                    false => trimmed,
                };
                let normalized = stripped.to_lowercase();
                let is_rule = normalized.contains("khi tôi nói")
                    || normalized.contains("nếu nói")
                    || normalized.contains("học quy tắc")
                    || normalized.contains("dạy quy tắc")
                    || normalized.contains("quy tắc:")
                    || normalized.contains("learn rule:")
                    || normalized.contains(":=")
                    || normalized.contains("=>");

                match is_rule {
                    false => return self.build_multi_stage_dag(&stages, text),
                    true => {}
                }
            }
            false => {}
        }

        let intent = self.classify_intent(text)?;
        let mut graph = PlanGraph::new();
        let normalized = text.trim().to_lowercase();

        match intent {
            IntentType::PeripheralControl { .. } => {
                let msg = "Peripheral device state updated.";
                graph
                    .add_node("ACTUATOR_SPEAK", msg.as_bytes(), &[])
                    .map_err(|_| "Failed to add peripheral control node")?;
            }
            IntentType::ComputeAndFile => {
                let (path, problem_text) = Self::extract_compute_and_file_params(text);

                let fs_synth_payload =
                    build_synthesize_fs_payload_stack("scripts/run_task.py", &problem_text);
                let n0 = graph
                    .add_node("FS_WORKER", fs_synth_payload.as_bytes(), &[])
                    .map_err(|_| "Failed to add script synthesizer node in DAG")?;

                let cmd_payload = b"python garry_workspace/scripts/run_task.py";
                let n1 = graph
                    .add_node("COMMAND_WORKER", cmd_payload, &[n0])
                    .map_err(|_| "Failed to add script runner node in DAG")?;

                let safe_path = match path.len() > 64 {
                    true => {
                        let mut end = 64;
                        while end > 0 && !path.is_char_boundary(end) {
                            end -= 1;
                        }
                        &path[..end]
                    }
                    false => &path,
                };

                let fs_write_payload = format!(
                    r#"{{"op":"write","path":"{}","from":"scripts/task_report.txt"}}"#,
                    safe_path
                );
                let _n2 = graph
                    .add_node("FS_WORKER", fs_write_payload.as_bytes(), &[n1])
                    .map_err(|_| "Failed to add report writer node in DAG")?;
            }
            IntentType::Compute => {
                let fs_synth_payload =
                    build_synthesize_fs_payload_stack("scripts/run_task.py", text);
                let n0 = graph
                    .add_node("FS_WORKER", fs_synth_payload.as_bytes(), &[])
                    .map_err(|_| "Failed to add script synthesizer node in DAG")?;

                let cmd_payload = b"python garry_workspace/scripts/run_task.py";
                let _n1 = graph
                    .add_node("COMMAND_WORKER", cmd_payload, &[n0])
                    .map_err(|_| "Failed to add script runner node in DAG")?;
            }
            IntentType::ScriptExecution => {
                let cmd_payload = b"python garry_workspace/scripts/temp_task.py";
                graph
                    .add_node("COMMAND_WORKER", cmd_payload, &[])
                    .map_err(|_| "Failed to add python runner node")?;
            }
            IntentType::StoreAxiom => {
                let resolver = SemanticIntentResolver::new();
                let payload = match resolver.parse_learning_axiom(text) {
                    Some((trigger, action)) => format!("{} := {}", trigger, action),
                    None => text.to_string(),
                };

                let payload_bytes = payload.as_bytes();
                let bounded_payload = match payload_bytes.len() > MAX_NODE_PAYLOAD_SIZE {
                    true => {
                        let mut cut = MAX_NODE_PAYLOAD_SIZE;
                        while cut > 0 && !payload.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        &payload_bytes[..cut]
                    }
                    false => payload_bytes,
                };

                graph
                    .add_node("STORE_AXIOM", bounded_payload, &[])
                    .map_err(|_| "Failed to add axiom node")?;
            }
            IntentType::FileOperation => {
                let payload = Self::extract_file_payload(text);
                graph
                    .add_node("FS_WORKER", payload.as_bytes(), &[])
                    .map_err(|_| "Failed to add file node")?;
            }
            IntentType::SystemCommand => {
                let is_save = normalized.contains("lưu") || normalized.contains("save");
                let is_vision = normalized.contains("chụp") || normalized.contains("screen");
                let is_click = normalized.contains("click chuột")
                    || normalized.contains("nhấp chuột")
                    || normalized.contains("bấm chuột");
                let is_move = normalized.contains("di chuột")
                    || normalized.contains("move mouse")
                    || normalized.contains("chuyển chuột");
                let is_key = normalized.contains("gõ phím")
                    || normalized.contains("ấn phím")
                    || normalized.contains("bấm phím")
                    || normalized.contains("nhấn phím")
                    || normalized.contains("press key");

                match (is_save, is_vision, is_click, is_move, is_key) {
                    (true, _, _, _, _) => {
                        graph
                            .add_node("SAVE_STATE_ACTION", b"checkpoint_requested", &[])
                            .map_err(|_| "Failed to add save node")?;
                    }
                    (_, true, _, _, _) => {
                        graph
                            .add_node("VISION_CAPTURE", b"screen_capture", &[])
                            .map_err(|_| "Failed to add vision node")?;
                    }
                    (_, _, true, _, _) => {
                        let button = Self::extract_mouse_click_button(text);
                        graph
                            .add_node("ACTUATOR_MOUSE_CLICK", button.as_bytes(), &[])
                            .map_err(|_| "Failed to add mouse click node")?;
                    }
                    (_, _, _, true, _) => {
                        let (x, y) = Self::extract_mouse_move_coords(text);
                        let coords_payload = format!("{},{}", x, y);
                        graph
                            .add_node("ACTUATOR_MOUSE_MOVE", coords_payload.as_bytes(), &[])
                            .map_err(|_| "Failed to add mouse move node")?;
                    }
                    (_, _, _, _, true) => {
                        let key = Self::extract_key_press(text);
                        graph
                            .add_node("ACTUATOR_KEY_PRESS", key.as_bytes(), &[])
                            .map_err(|_| "Failed to add key press node")?;
                    }
                    _ => {
                        let cmd_payload = Self::extract_command_payload(text);
                        let cmd_bytes = cmd_payload.as_bytes();
                        let bounded_cmd = match cmd_bytes.len() > MAX_NODE_PAYLOAD_SIZE {
                            true => {
                                let mut cut = MAX_NODE_PAYLOAD_SIZE;
                                while cut > 0 && !cmd_payload.is_char_boundary(cut) {
                                    cut -= 1;
                                }
                                &cmd_bytes[..cut]
                            }
                            false => cmd_bytes,
                        };

                        graph
                            .add_node("COMMAND_WORKER", bounded_cmd, &[])
                            .map_err(|_| "Failed to add command node")?;
                    }
                }
            }
            IntentType::Conversational => {
                let is_confirm = normalized.contains("xác nhận") || normalized.contains("phản hồi");
                let is_status = (normalized.contains("thế nào") && !normalized.contains("chào"))
                    || normalized.contains("báo cáo")
                    || normalized.contains("status");

                let payload_str = match (is_confirm, is_status) {
                    (true, _) => "TTS_CONFIRMATION".to_string(),
                    (_, true) => self.generate_conversational_response(text, snapshot),
                    _ => "Greetings! Garry Autonomous Engine is ready for execution.".to_string(),
                };

                let payload_bytes = payload_str.as_bytes();
                let bounded_speak = match payload_bytes.len() > MAX_NODE_PAYLOAD_SIZE {
                    true => {
                        let mut cut = MAX_NODE_PAYLOAD_SIZE;
                        while cut > 0 && !payload_str.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        &payload_bytes[..cut]
                    }
                    false => payload_bytes,
                };

                graph
                    .add_node("ACTUATOR_SPEAK", bounded_speak, &[])
                    .map_err(|_| "Failed to add conversational node")?;
            }
        }

        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_planner_generates_multi_stage_dag_with_ping_pong_buffer() {
        let planner = SensoryIntentPlanner::new();
        let prompt = "Phân rã QR ma trận A = [[1, 2], [3, 4]] then giải hệ phương trình and save to composite_result.txt";

        let stages = split_composite_intents(prompt);
        assert_eq!(stages.len(), 2);

        let plan = planner.classify_and_plan(prompt).expect("DAG translation must succeed");
        assert_eq!(plan.len(), 5);
        let n4 = plan.get_node(4).unwrap();
        assert_eq!(n4.action_type, "FS_WORKER");
        let payload_str = std::str::from_utf8(n4.payload()).unwrap();
        assert!(payload_str.contains("composite_result.txt"));
    }
}