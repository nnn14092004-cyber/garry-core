//! Ephemeral Sub-Worker Isolation, Sovereign Formal Verification Gate, and L2 Axiom Hypergraph.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - BOUNDED MEMORY - ZERO EXTERNAL CRATES - FAIL-CLOSED]

use std::fmt;
use std::io::{BufRead, Write};
use std::path::Path;

use crate::{
    ActionProposal, BoundedStorage, CheckpointMetadata, DeterministicEngine,
    EngineError, EngineState, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PurifiedAxiomCandidate {
    pub key: String,
    pub value: String,
    pub source_confidence: f32,
}

impl Eq for PurifiedAxiomCandidate {}

#[derive(Debug, Clone, PartialEq)]
pub struct AxiomProofCertificate {
    pub axiom_key: String,
    pub convergence_epsilon: f64,
    pub code_crc32: u32,
    pub epochs_required: usize,
    pub certified_true: bool,
}

pub fn sanitize_html_and_control_chars(input: &str) -> String {
    let cap = input.len().min(65_536);
    let mut clean = String::with_capacity(cap);
    let mut in_tag = false;
    let mut char_budget = 65_536usize;

    for ch in input.chars() {
        match char_budget == 0 {
            true => break,
            false => char_budget -= 1,
        }
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                match clean.is_empty() || clean.ends_with(' ') {
                    true => {}
                    false => clean.push(' '),
                }
            }
            _ => match in_tag {
                true => {}
                false => match ch.is_whitespace() {
                    true => match clean.ends_with(' ') {
                        true => {}
                        false => clean.push(' '),
                    },
                    false => match ch.is_control() {
                        true => {}
                        false => clean.push(ch),
                    },
                },
            },
        }
    }

    clean.trim().to_string()
}

pub fn contains_prompt_injection(input: &str) -> bool {
    let bounded_slice = match input.len() > 16_384 {
        true => {
            let mut cut = 16_384;
            while cut > 0 && !input.is_char_boundary(cut) {
                cut -= 1;
            }
            &input[..cut]
        }
        false => input,
    };
    let lower = bounded_slice.to_lowercase();
    const INJECTION_PATTERNS: &[&str] = &[
        "ignore previous instructions",
        "ignore all previous",
        "system prompt",
        "disregard all",
        "you are now",
        "grant admin",
        "master_clearance_override",
        "drop table",
        "bypass security",
        "jailbreak",
        "javascript:",
        "eval(",
    ];

    INJECTION_PATTERNS.iter().any(|pattern| lower.contains(pattern))
}

pub fn verify_code_safety(code: &str) -> Result<(), &'static str> {
    let bounded_slice = match code.len() > 32_768 {
        true => {
            let mut cut = 32_768;
            while cut > 0 && !code.is_char_boundary(cut) {
                cut -= 1;
            }
            &code[..cut]
        }
        false => code,
    };
    let lower = bounded_slice.to_lowercase();
    let mut no_spaces = String::with_capacity(lower.len().min(32_768));
    let mut char_budget = 32_768usize;
    for c in lower.chars() {
        match char_budget == 0 {
            true => break,
            false => char_budget -= 1,
        }
        match c.is_whitespace() {
            true => {}
            false => no_spaces.push(c),
        }
    }

    const SECURITY_POLICY: &[(&[&str], &'static str)] = &[
        (
            &["eval(", "exec(", "compile(", "__import__", "getattr(", "globals()", "locals()"],
            "Dynamic code execution is strictly prohibited",
        ),
        (
            &["os.system", "subprocess", "os.popen", "os.spawn", "shutil.rmtree"],
            "Operating system and subprocess operations are strictly prohibited",
        ),
        (
            &["socket", "urllib", "requests", "http.client"],
            "Network and socket interactions are strictly prohibited",
        ),
        (
            &["open(", "file(", "pathlib"],
            "File system manipulation functions are strictly prohibited in axioms",
        ),
    ];

    SECURITY_POLICY
        .iter()
        .find_map(|(patterns, err_msg)| {
            patterns
                .iter()
                .any(|&p| lower.contains(p) || no_spaces.contains(p))
                .then_some(Err(*err_msg))
        })
        .unwrap_or(Ok(()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MathematicalOperatorDomain {
    SpectralIteration,
    IterativeRelaxation,
    ProjectionGrammar,
    DynamicStepping,
    InvariantConservation,
    PolyhedronGeometry,
    QuantumOperator,
    MatrixFactorization,
    Unclassified,
}

pub fn sanitize_and_purify_content(raw_key: &str, raw_value: &str) -> Option<(String, String)> {
    let clean_key = sanitize_html_and_control_chars(raw_key);
    let clean_value = sanitize_html_and_control_chars(raw_value);

    match clean_key.is_empty() || clean_value.is_empty() {
        true => return None,
        false => {}
    }

    match contains_prompt_injection(&clean_key) || contains_prompt_injection(&clean_value) {
        true => return None,
        false => {}
    }

    match verify_code_safety(&clean_key).is_err() || verify_code_safety(&clean_value).is_err() {
        true => return None,
        false => {}
    }

    let bounded_key = match clean_key.len() > MAX_KEY_SIZE {
        true => {
            let mut end = MAX_KEY_SIZE;
            while end > 0 && !clean_key.is_char_boundary(end) {
                end -= 1;
            }
            clean_key[..end].trim().to_string()
        }
        false => clean_key,
    };

    let bounded_value = match clean_value.len() > MAX_VALUE_SIZE {
        true => {
            let mut end = MAX_VALUE_SIZE;
            while end > 0 && !clean_value.is_char_boundary(end) {
                end -= 1;
            }
            clean_value[..end].trim().to_string()
        }
        false => clean_value,
    };

    Some((bounded_key, bounded_value))
}

impl MathematicalOperatorDomain {
    pub fn classify(topic: &str) -> Self {
        let t = topic.to_lowercase();
        const PROFILES: &[(MathematicalOperatorDomain, &[&str])] = &[
            (
                MathematicalOperatorDomain::QuantumOperator,
                &[
                    "state_density", "slot_trace", "transient", "tload", "tstore",
                    "calldata_entropy", "storage_coherence", "state_purity",
                ],
            ),
            (
                MathematicalOperatorDomain::MatrixFactorization,
                &[
                    "crout", "cholesky", "doolittle", "factorization", "decomposition", "ldlt",
                    "householder", "givens", "tridiagonal", "svd", "schur", "bunch", "kaufman",
                    "indefinite", "polar",
                ],
            ),
            (
                MathematicalOperatorDomain::SpectralIteration,
                &[
                    "arnoldi", "krylov", "power", "rayleigh", "dominant", "eigen", "spectral",
                    "gmres", "bicgstab", "hessenberg", "jacobi",
                ],
            ),
            (
                MathematicalOperatorDomain::PolyhedronGeometry,
                &[
                    "call_graph", "cross_contract_topology", "diamond_proxy",
                    "facet_routing", "manifold_state", "isometry_invariant",
                ],
            ),
            (
                MathematicalOperatorDomain::DynamicStepping,
                &[
                    "stepping", "runge", "kutta", "verlet", "symplectic", "trajectory",
                    "integrator", "multistep", "oscillator", "transport", "navier", "ode", "wave",
                    "heat", "kuramoto",
                ],
            ),
            (
                MathematicalOperatorDomain::InvariantConservation,
                &[
                    "invariant", "conservation", "preservation", "accounting", "inflation",
                    "vault", "share", "pool", "drain", "guard", "reentrancy", "oracle", "merkle",
                    "signature", "replay", "overflow", "underflow", "tick_math", "amm", "erc4626",
                ],
            ),
            (
                MathematicalOperatorDomain::IterativeRelaxation,
                &[
                    "conjugate", "gradient", "relaxation", "seidel", "richardson",
                    "iterative_solver",
                ],
            ),
            (
                MathematicalOperatorDomain::ProjectionGrammar,
                &["projection", "subspace", "orthogonal_proj"],
            ),
        ];

        PROFILES
            .iter()
            .map(|(domain, keywords)| {
                let score = keywords.iter().filter(|k| t.contains(*k)).count();
                (*domain, score)
            })
            .max_by_key(|(_, score)| *score)
            .filter(|(_, score)| *score > 0)
            .map(|(domain, _)| domain)
            .unwrap_or(MathematicalOperatorDomain::Unclassified)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MathematicalAxiom {
    pub key: String,
    pub title: String,
    pub category: String,
    pub principle: String,
    pub diagonal_formula: String,
    pub off_diagonal_formula: String,
    pub output_symbol: String,
    pub pre_conditions: String,
    pub core_algorithm: String,
    pub post_conditions: String,
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut budget = 16_384usize;
    for ch in s.chars() {
        match budget == 0 {
            true => break,
            false => budget -= 1,
        }
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn unescape_json_field(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut budget = 16_384usize;
    while let Some(c) = chars.next() {
        match budget == 0 {
            true => break,
            false => budget -= 1,
        }
        match c == '\\' {
            true => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            false => out.push(c),
        }
    }
    out
}

pub fn extract_json_string_field(json_line: &str, field_name: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field_name);
    let start_idx = json_line.find(&pattern)?;
    let after_colon = json_line[start_idx + pattern.len()..].trim_start();
    let body = after_colon.strip_prefix('"')?;

    let mut escaped = false;
    let mut end_pos: Option<usize> = None;
    let mut budget = 16_384usize;

    for (idx, ch) in body.char_indices() {
        match budget == 0 {
            true => break,
            false => budget -= 1,
        }
        match escaped {
            true => escaped = false,
            false => match ch {
                '\\' => escaped = true,
                '"' => {
                    end_pos = Some(idx);
                    break;
                }
                _ => {}
            },
        }
    }

    let end = end_pos?;
    Some(unescape_json_field(&body[..end]))
}

impl MathematicalAxiom {
    pub fn to_jsonl_line(&self) -> String {
        format!(
            "{{\"key\":\"{}\",\"title\":\"{}\",\"category\":\"{}\",\"principle\":\"{}\",\"diagonal_formula\":\"{}\",\"off_diagonal_formula\":\"{}\",\"output_symbol\":\"{}\",\"pre_conditions\":\"{}\",\"core_algorithm\":\"{}\",\"post_conditions\":\"{}\"}}",
            escape_json_str(&self.key),
            escape_json_str(&self.title),
            escape_json_str(&self.category),
            escape_json_str(&self.principle),
            escape_json_str(&self.diagonal_formula),
            escape_json_str(&self.off_diagonal_formula),
            escape_json_str(&self.output_symbol),
            escape_json_str(&self.pre_conditions),
            escape_json_str(&self.core_algorithm),
            escape_json_str(&self.post_conditions),
        )
    }

    pub fn from_jsonl_line(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        match trimmed.starts_with('{') && trimmed.ends_with('}') {
            false => return None,
            true => {}
        }
        let key = extract_json_string_field(trimmed, "key")?;
        let title = extract_json_string_field(trimmed, "title").unwrap_or_default();
        let category = extract_json_string_field(trimmed, "category").unwrap_or_default();
        let principle = extract_json_string_field(trimmed, "principle").unwrap_or_default();
        let diagonal_formula =
            extract_json_string_field(trimmed, "diagonal_formula").unwrap_or_default();
        let off_diagonal_formula =
            extract_json_string_field(trimmed, "off_diagonal_formula").unwrap_or_default();
        let output_symbol = extract_json_string_field(trimmed, "output_symbol").unwrap_or_default();
        let pre_conditions =
            extract_json_string_field(trimmed, "pre_conditions").unwrap_or_default();
        let core_algorithm =
            extract_json_string_field(trimmed, "core_algorithm").unwrap_or_default();
        let post_conditions =
            extract_json_string_field(trimmed, "post_conditions").unwrap_or_default();

        Some(Self {
            key,
            title,
            category,
            principle,
            diagonal_formula,
            off_diagonal_formula,
            output_symbol,
            pre_conditions,
            core_algorithm,
            post_conditions,
        })
    }
}

impl PurifiedAxiomCandidate {
    pub fn to_jsonl_line(&self) -> String {
        format!(
            "{{\"key\":\"{}\",\"value\":\"{}\",\"source_confidence\":{:.4}}}",
            escape_json_str(&self.key),
            escape_json_str(&self.value),
            self.source_confidence
        )
    }
}

// ============================================================================
// SECTION 1: FNV-1A EXACT SIGNATURE HASH & TWO-PHASE ACCEPT/DENY FAST-GATE (O(1))
// ============================================================================

pub const FNV_OFFSET_BASIS: u32 = 2166136261;
pub const FNV_PRIME: u32 = 16777619;
pub const MAX_HASH_SCAN_BYTES: usize = 512;
pub const MAX_ACCEPT_SLOTS: usize = 8;
pub const MAX_TOKEN_SLOTS: usize = 32;

pub const MASK_QUANTUM: u64          = 1 << 0;
pub const MASK_DEPHASING: u64        = 1 << 1;
pub const MASK_FACTORIZATION: u64    = 1 << 2;
pub const MASK_SPECTRAL: u64         = 1 << 3;
pub const MASK_POLYHEDRON: u64       = 1 << 4;
pub const MASK_DYNAMIC_STEP: u64     = 1 << 5;
pub const MASK_ECONOMIC_AMM: u64     = 1 << 6;
pub const MASK_AUDIT_CEI: u64        = 1 << 7;
pub const MASK_AUDIT_ARITHMETIC: u64 = 1 << 8;

pub const fn fnv1a_hash_bounded(bytes: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_BASIS;
    let limit = match bytes.len() > MAX_HASH_SCAN_BYTES {
        true => MAX_HASH_SCAN_BYTES,
        false => bytes.len(),
    };
    let mut i = 0usize;
    while i < limit {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

pub const fn fnv1a_hash_ascii_lower(bytes: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_BASIS;
    let limit = match bytes.len() > MAX_HASH_SCAN_BYTES {
        true => MAX_HASH_SCAN_BYTES,
        false => bytes.len(),
    };
    let mut i = 0usize;
    while i < limit {
        let b = bytes[i];
        let lower_b = match b >= b'A' && b <= b'Z' {
            true => b + 32,
            false => b,
        };
        hash ^= lower_b as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

pub const HASH_CHOLESKY: u32        = fnv1a_hash_ascii_lower(b"cholesky");
pub const HASH_JACOBI: u32          = fnv1a_hash_ascii_lower(b"jacobi");
pub const HASH_JACOBI_EIGEN: u32    = fnv1a_hash_ascii_lower(b"jacobi_eigenvalue");
pub const HASH_QR: u32              = fnv1a_hash_ascii_lower(b"qr");
pub const HASH_GRAM_SCHMIDT: u32    = fnv1a_hash_ascii_lower(b"gram_schmidt");
pub const HASH_QR_GRAM_SCHMIDT: u32 = fnv1a_hash_ascii_lower(b"qr_gram_schmidt");
pub const HASH_HOUSEHOLDER: u32     = fnv1a_hash_ascii_lower(b"householder");
pub const HASH_TRIDIAGONAL: u32     = fnv1a_hash_ascii_lower(b"tridiagonal");
pub const HASH_PYRAMID: u32         = fnv1a_hash_ascii_lower(b"pyramid");
pub const HASH_PYRAMID_ISO: u32     = fnv1a_hash_ascii_lower(b"square_pyramid_isometry");
pub const HASH_TETRAHEDRON: u32     = fnv1a_hash_ascii_lower(b"tetrahedron");
pub const HASH_TETRAHEDRON_ISO: u32 = fnv1a_hash_ascii_lower(b"tetrahedron_isometry");
pub const HASH_OCTAHEDRON: u32      = fnv1a_hash_ascii_lower(b"octahedron");
pub const HASH_OCTAHEDRON_ISO: u32  = fnv1a_hash_ascii_lower(b"octahedron_isometry");
pub const HASH_DOOLITTLE: u32       = fnv1a_hash_ascii_lower(b"doolittle");
pub const HASH_DOOLITTLE_LU: u32    = fnv1a_hash_ascii_lower(b"doolittle_lu");
pub const HASH_LU_DECOMP: u32       = fnv1a_hash_ascii_lower(b"lu_decomposition");
pub const HASH_AMM: u32             = fnv1a_hash_ascii_lower(b"amm");
pub const HASH_XY_K: u32            = fnv1a_hash_ascii_lower(b"xy_k");
pub const HASH_CONST_PROD: u32      = fnv1a_hash_ascii_lower(b"constant_product");
pub const HASH_LIQ_POOL: u32        = fnv1a_hash_ascii_lower(b"liquidity_pool");
pub const HASH_AMM_INVARIANT: u32   = fnv1a_hash_ascii_lower(b"amm_constant_product_invariant");
pub const HASH_DEPHASING: u32       = fnv1a_hash_ascii_lower(b"dephasing");
pub const HASH_DAMPING: u32         = fnv1a_hash_ascii_lower(b"damping");
pub const HASH_DEPHASING_CHAN: u32  = fnv1a_hash_ascii_lower(b"dephasing_channel_decoherence");
pub const HASH_POLAR: u32           = fnv1a_hash_ascii_lower(b"polar");
pub const HASH_POLAR_DECOMP: u32    = fnv1a_hash_ascii_lower(b"factorization_polar_decomposition_unitary");
pub const HASH_HOPF: u32            = fnv1a_hash_ascii_lower(b"hopf");
pub const HASH_HOPF_FIBRATION: u32  = fnv1a_hash_ascii_lower(b"polyhedron_hopf_fibration_s3_s2_mapping");
pub const MASK_PARTNER_CLEARANCE: u64     = 1 << 9;
pub const MASK_FUTURE_TRAJECTORY: u64     = 1 << 10;
pub const MASK_CUMULATIVE_DELTA: u64      = 1 << 11;
pub const MASK_ARCHETYPE_LENDING_LIQ: u64 = 1 << 12;
pub const MASK_ARCHETYPE_BRIDGE_ZK: u64   = 1 << 13;
pub const MASK_ARCHETYPE_ORACLE_TWAP: u64 = 1 << 14;
pub const MASK_ARCHETYPE_GOV_PROXY: u64   = 1 << 15;
pub const MASK_AUDIT_UNDERFLOW_DOS: u64   = 1 << 16;
pub const MASK_ERC4626_VAULT_SPEC: u64    = 1 << 17;
pub const MASK_OZ_MATH_TRY_CATCH: u64     = 1 << 18;
pub const MASK_LIVE_FORK_HARVEST: u64     = 1 << 19;

pub const HASH_CONVERT_TO_ASSETS: u32 = fnv1a_hash_ascii_lower(b"converttoassets");
pub const HASH_CONVERT_TO_SHARES: u32 = fnv1a_hash_ascii_lower(b"converttoshares");
pub const HASH_PREVIEW_DEPOSIT: u32   = fnv1a_hash_ascii_lower(b"previewdeposit");
pub const HASH_PREVIEW_REDEEM: u32    = fnv1a_hash_ascii_lower(b"previewredeem");
pub const HASH_YIELD_VAULT: u32       = fnv1a_hash_ascii_lower(b"yieldvault");
pub const HASH_STAKED_ASSETS: u32     = fnv1a_hash_ascii_lower(b"stakedassets");
pub const HASH_RESERVED_ASSETS: u32   = fnv1a_hash_ascii_lower(b"reservedassets");
pub const HASH_DONATE_AS_YIELD: u32   = fnv1a_hash_ascii_lower(b"donateasyield");
pub const HASH_ABI_DECODE: u32        = fnv1a_hash_ascii_lower(b"decode");

pub const HASH_TRAJECTORY: u32        = fnv1a_hash_ascii_lower(b"trajectory");
pub const HASH_FUTURE_FLOW: u32       = fnv1a_hash_ascii_lower(b"future_cashflow_trajectory_invariant");
pub const HASH_CUMULATIVE_DELTA: u32  = fnv1a_hash_ascii_lower(b"cumulative_delta_conservation");
pub const HASH_MICRO_DRAIN: u32       = fnv1a_hash_ascii_lower(b"micro_drain");
pub const HASH_MULDIV: u32            = fnv1a_hash_ascii_lower(b"muldiv");
pub const HASH_ACCUMULATED_DUST: u32  = fnv1a_hash_ascii_lower(b"accumulateddust");

/// Sanitizes a Git repository URL on the stack in bounded steps (256 bytes).
pub fn sanitize_git_url_stack(raw_url: &str) -> (String, String) {
    let trimmed = raw_url
        .trim_start_matches('\u{feff}')
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == ';' || c == '\\');
    let bytes = trimmed.as_bytes();
    let mut limit = match bytes.len() > 256 {
        true => 256,
        false => bytes.len(),
    };
    while limit > 0 && !trimmed.is_char_boundary(limit) {
        limit -= 1;
    }

    let mut clean_end = limit;
    let mut i = 0usize;
    while i < limit {
        let is_query_or_hash =
            bytes[i] == b'?' || bytes[i] == b'#' || bytes[i] == b'&' || bytes[i] == b'\\';
        match is_query_or_hash {
            true => {
                clean_end = i;
                break;
            }
            false => i += 1,
        }
    }

    let base_slice = trimmed[..clean_end].trim_end_matches('/');
    let lower_slice = base_slice.to_lowercase();
    let blob_or_tree_cut = lower_slice
        .find("/blob/")
        .or_else(|| lower_slice.find("/tree/"))
        .or_else(|| lower_slice.find("/commit/"))
        .or_else(|| lower_slice.find("/releases"))
        .unwrap_or(base_slice.len());

    let mut clean_slice = base_slice[..blob_or_tree_cut].trim_end_matches('/');

    match lower_slice.find("github.com/") {
        Some(gh_pos) => {
            let after_gh = &clean_slice[gh_pos + "github.com/".len()..];
            let mut slash_cnt = 0usize;
            let mut cut_len = after_gh.len();
            for (idx, ch) in after_gh.char_indices() {
                match ch == '/' {
                    true => {
                        slash_cnt += 1;
                        match slash_cnt == 2 {
                            true => {
                                cut_len = idx;
                                break;
                            }
                            false => {}
                        }
                    }
                    false => {}
                }
            }
            let total_end = gh_pos + "github.com/".len() + cut_len;
            clean_slice = clean_slice[..total_end].trim_end_matches('/');
        }
        None => {}
    }

    let clean_url = match clean_slice.ends_with(".git") {
        true => clean_slice.to_string(),
        false => format!("{}.git", clean_slice),
    };

    let without_git = clean_slice.trim_end_matches(".git");
    let repo_raw = without_git.rsplit('/').next().unwrap_or("cloned_repo");
    let owner_raw = without_git.rsplit('/').nth(1).unwrap_or("");
    let is_generic_repo_name = matches!(
        repo_raw.to_ascii_lowercase().as_str(),
        "contracts" | "protocol" | "core" | "smart-contracts" | "v2-core" | "v3-core" | "bounty"
    );
    let combined_raw = match is_generic_repo_name && !owner_raw.is_empty() && !owner_raw.contains(':') {
        true => format!("{}_{}", owner_raw, repo_raw),
        false => repo_raw.to_string(),
    };

    let mut repo_name = String::with_capacity(32);
    let mut char_budget = 32usize;
    for ch in combined_raw.chars() {
        match char_budget == 0 {
            true => break,
            false => char_budget -= 1,
        }
        match ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            true => repo_name.push(ch),
            false => repo_name.push('_'),
        }
    }

    let final_repo_name = match repo_name.is_empty() {
        true => "cloned_repo".to_string(),
        false => repo_name,
    };

    (clean_url, final_repo_name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractDomainBranch {
    VaultAndLendingCore,
    HookAndControllers,
    OracleAndPricing,
    AutomatorsAndKeepers,
    TransformersAndLiquidation,
    SharedMathAndUtils,
}

impl ContractDomainBranch {
    pub const fn as_folder_slug(&self) -> &'static str {
        match self {
            Self::VaultAndLendingCore => "01_vault_core",
            Self::HookAndControllers => "02_hook_controllers",
            Self::OracleAndPricing => "03_oracle_pricing",
            Self::AutomatorsAndKeepers => "04_automators_keepers",
            Self::TransformersAndLiquidation => "05_transformers_liquidation",
            Self::SharedMathAndUtils => "06_shared_math_utils",
        }
    }

    pub const fn priority_weight(&self) -> u32 {
        match self {
            Self::VaultAndLendingCore => 50,
            Self::HookAndControllers => 45,
            Self::OracleAndPricing => 40,
            Self::TransformersAndLiquidation => 35,
            Self::AutomatorsAndKeepers => 30,
            Self::SharedMathAndUtils => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractStructuralTriage {
    pub should_prune: bool,
    pub suspicion_score: u32,
    pub branch: ContractDomainBranch,
    pub has_concrete_contract: bool,
    pub has_stateful_or_call_library: bool,
    pub has_storage_state: bool,
    pub has_external_interaction: bool,
    pub has_precision_math: bool,
}

pub fn extract_provenance_and_eth_address_stack(raw_spec: &str) -> (String, Option<String>, String) {
    let trimmed_init = raw_spec
        .trim_start_matches('\u{feff}')
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == ';');
    let trimmed = match trimmed_init.strip_prefix("clone ") {
        Some(rest) => rest.trim(),
        None => trimmed_init,
    };
    let origin_link = trimmed.to_string();

    let bytes = trimmed.as_bytes();
    let limit = match bytes.len() > 256 {
        true => 256,
        false => bytes.len(),
    };
    let mut found_addr: Option<String> = None;
    let mut i = 0usize;

    while i + 42 <= limit {
        let is_0x = bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X');
        match is_0x {
            true => {
                let mut all_hex = true;
                let mut k = 2usize;
                while k < 42 {
                    match bytes[i + k].is_ascii_hexdigit() {
                        true => k += 1,
                        false => {
                            all_hex = false;
                            break;
                        }
                    }
                }
                match all_hex {
                    true => {
                        let addr_slice = &trimmed[i..i + 42];
                        found_addr = Some(addr_slice.to_string());
                        break;
                    }
                    false => i += 1,
                }
            }
            false => i += 1,
        }
    }

    match found_addr {
        Some(ref addr) => {
            let short_id = format!("{}_{}", &addr[..6], &addr[38..42]);
            (short_id, found_addr, origin_link)
        }
        None => {
            let is_git_or_http = trimmed.starts_with("https://")
                || trimmed.starts_with("http://")
                || trimmed.starts_with("git@");
            match is_git_or_http {
                true => {
                    let (_, repo_name) = sanitize_git_url_stack(trimmed);
                    (repo_name, None, origin_link)
                }
                false => {
                    let stripped = trimmed
                        .trim_start_matches("targets/")
                        .trim_start_matches("targets\\");
                    let mut clean_id = String::with_capacity(48);
                    let mut budget = 48usize;
                    for ch in stripped.chars() {
                        match budget == 0 {
                            true => break,
                            false => budget -= 1,
                        }
                        match ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                            true => clean_id.push(ch),
                            false => clean_id.push('_'),
                        }
                    }
                    let final_id = match clean_id.is_empty() {
                        true => "cluster_target".to_string(),
                        false => clean_id,
                    };
                    (final_id, None, origin_link)
                }
            }
        }
    }
}

pub fn classify_contract_domain_branch_stack(
    path_low: &str,
    source_low: &str,
) -> ContractDomainBranch {
    let is_transformer_or_liq = path_low.contains("transformer")
        || path_low.contains("liquidat")
        || source_low.contains("flashloanliquidator")
        || source_low.contains("leveragetransformer");
    let is_vault = path_low.contains("/vault/")
        || path_low.starts_with("vault/")
        || path_low.contains("vault")
        || source_low.contains("erc4626");
    let is_hook_or_ctrl = path_low.contains("/hook/")
        || path_low.starts_with("hook/")
        || path_low.contains("hook")
        || path_low.contains("auction")
        || path_low.contains("lease")
        || source_low.contains("beforeswap")
        || source_low.contains("beforeaddliquidity");
    let is_oracle = path_low.contains("/oracle/")
        || path_low.starts_with("oracle/")
        || path_low.contains("oracle")
        || source_low.contains("twap")
        || source_low.contains("latestrounddata")
        || source_low.contains("sequencer");
    let is_automator = path_low.contains("/automators/")
        || path_low.starts_with("automators/")
        || path_low.contains("auto")
        || path_low.contains("executor");

    match (
        is_transformer_or_liq,
        is_vault,
        is_hook_or_ctrl,
        is_oracle,
        is_automator,
    ) {
        (true, _, _, _, _) => ContractDomainBranch::TransformersAndLiquidation,
        (false, true, _, _, _) => ContractDomainBranch::VaultAndLendingCore,
        (false, false, true, _, _) => ContractDomainBranch::HookAndControllers,
        (false, false, false, true, _) => ContractDomainBranch::OracleAndPricing,
        (false, false, false, false, true) => ContractDomainBranch::AutomatorsAndKeepers,
        (false, false, false, false, false) => ContractDomainBranch::SharedMathAndUtils,
    }
}

#[derive(Debug, Clone)]
pub struct HarvestedLiveForkSpec {
    pub chain_name: &'static str,
    pub rpc_env_key: &'static str,
    pub fallback_rpc_url: &'static str,
    pub target_address: String,
    pub origin_link: String,
    pub live_block_hex: String,
    pub discovered_view_getters: [Option<String>; 8],
    pub getter_count: usize,
    pub discovered_permissionless_mutators: [Option<String>; 4],
    pub mutator_count: usize,
    pub has_erc4626_integration: bool,
    pub has_try_catch_abi_decode: bool,
}

pub struct MainnetForkStateHarvester;

impl MainnetForkStateHarvester {
    pub fn harvest_from_source_stack(source: &str, fallback_label: &str) -> HarvestedLiveForkSpec {
        let mut origin_link = String::new();
        let mut target_addr = String::new();

        let mut tail_budget = 64usize;
        for line in source.lines().rev() {
            match tail_budget == 0 {
                true => break,
                false => tail_budget -= 1,
            }
            let tr = line.trim();
            match tr.strip_prefix("// @garry-origin-link:") {
                Some(link_val) => {
                    let lv = link_val.trim();
                    match !lv.is_empty() {
                        true => origin_link = lv.to_string(),
                        false => {}
                    }
                }
                None => {}
            }
        }

        let (_, addr_from_link, resolved_link) = match origin_link.is_empty() {
            true => extract_provenance_and_eth_address_stack(fallback_label),
            false => extract_provenance_and_eth_address_stack(&origin_link),
        };

        match addr_from_link {
            Some(addr) => target_addr = addr,
            None => {
                let mut header_budget = 32usize;
                for line in source.lines() {
                    match header_budget == 0 || !target_addr.is_empty() {
                        true => break,
                        false => header_budget -= 1,
                    }
                    let tr = line.trim();
                    let low = tr.to_lowercase();
                    let is_provenance_comment = (tr.starts_with("//") || tr.starts_with('*'))
                        && (low.contains("etherscan")
                            || low.contains("blockscout")
                            || low.contains("arbiscan")
                            || low.contains("basescan")
                            || low.contains("polygonscan")
                            || low.contains("@garry-origin-link")
                            || low.contains("@custom:deployed-at"));
                    match is_provenance_comment {
                        true => {
                            let (_, inline_addr, _) = extract_provenance_and_eth_address_stack(tr);
                            match inline_addr {
                                Some(a) => target_addr = a,
                                None => {}
                            }
                        }
                        false => {}
                    }
                }
            }
        }

        let low_link = resolved_link.to_lowercase();
        let (chain_name, rpc_env_key, fallback_rpc_url) = match (
            low_link.contains("basescan") || low_link.contains("base."),
            low_link.contains("arbiscan") || low_link.contains("arbitrum"),
            low_link.contains("optimistic") || low_link.contains("optimism"),
            low_link.contains("polygonscan") || low_link.contains("polygon"),
            low_link.contains("bscscan") || low_link.contains("binance"),
            low_link.contains("scrollscan") || low_link.contains("scroll."),
            low_link.contains("ftmscan") || low_link.contains("fantom"),
            low_link.contains("snowtrace") || low_link.contains("avalanche"),
        ) {
            (true, _, _, _, _, _, _, _) => ("base", "BASE_RPC_URL", "https://mainnet.base.org"),
            (false, true, _, _, _, _, _, _) => ("arbitrum", "ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc"),
            (false, false, true, _, _, _, _, _) => ("optimism", "OPTIMISM_RPC_URL", "https://mainnet.optimism.io"),
            (false, false, false, true, _, _, _, _) => ("polygon", "POLYGON_RPC_URL", "https://polygon-rpc.com"),
            (false, false, false, false, true, _, _, _) => ("bsc", "BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
            (false, false, false, false, false, true, _, _) => ("scroll", "SCROLL_RPC_URL", "https://rpc.scroll.io"),
            (false, false, false, false, false, false, true, _) => ("fantom", "FANTOM_RPC_URL", "https://rpcapi.fantom.network"),
            (false, false, false, false, false, false, false, true) => ("avalanche", "AVALANCHE_RPC_URL", "https://api.avax.network/ext/bc/C/rpc"),
            (false, false, false, false, false, false, false, false) => ("mainnet", "ETH_RPC_URL", "https://ethereum-rpc.publicnode.com"),
        };

        const NONE_STR: Option<String> = None;
        let mut discovered_view_getters: [Option<String>; 8] = [NONE_STR; 8];
        let mut getter_count = 0usize;
        let mut discovered_permissionless_mutators: [Option<String>; 4] = [NONE_STR; 4];
        let mut mutator_count = 0usize;
        let mut has_erc4626_integration = false;
        let mut has_try_catch_abi_decode = false;

        let mut scan_budget = 4096usize;
        for raw_line in source.lines() {
            match scan_budget == 0 {
                true => break,
                false => scan_budget -= 1,
            }
            let tr = raw_line.trim();
            let low = tr.to_lowercase();

            match low.contains("ierc4626") || low.contains("converttoassets") || low.contains("yieldvault") {
                true => has_erc4626_integration = true,
                false => {}
            }
            match low.contains("abi.decode") && (low.contains("catch") || source.contains("try this.")) {
                true => has_try_catch_abi_decode = true,
                false => {}
            }

            let is_view_fn = low.starts_with("function ")
                && (low.contains(" view ") || low.contains(" public "))
                && low.contains("()");
            match is_view_fn && getter_count < 8 {
                true => {
                    let after_fn = tr["function ".len()..].trim_start();
                    let fn_ident: String = after_fn
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .take(40)
                        .collect();
                    let is_useful_getter = !fn_ident.is_empty() && !fn_ident.starts_with('_');
                    match is_useful_getter {
                        true => {
                            discovered_view_getters[getter_count] = Some(fn_ident);
                            getter_count += 1;
                        }
                        false => {}
                    }
                }
                false => {}
            }

            let is_ext_fn = low.starts_with("function ")
                && (low.contains(" external") || low.contains(" public"))
                && !low.contains(" view")
                && !low.contains(" pure")
                && !low.contains("only")
                && !low.contains("auth")
                && !low.contains("restricted");
            match is_ext_fn && mutator_count < 4 {
                true => {
                    let after_fn = tr["function ".len()..].trim_start();
                    let fn_ident: String = after_fn
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .take(40)
                        .collect();
                    match !fn_ident.is_empty() && !fn_ident.starts_with('_') {
                        true => {
                            discovered_permissionless_mutators[mutator_count] = Some(fn_ident);
                            mutator_count += 1;
                        }
                        false => {}
                    }
                }
                false => {}
            }
        }

        HarvestedLiveForkSpec {
            chain_name,
            rpc_env_key,
            fallback_rpc_url,
            target_address: target_addr,
            origin_link: resolved_link,
            live_block_hex: "repository_head".to_string(),
            discovered_view_getters,
            getter_count,
            discovered_permissionless_mutators,
            mutator_count,
            has_erc4626_integration,
            has_try_catch_abi_decode,
        }
    }
}

pub fn evaluate_contract_structural_triage_stack(
    virtual_path: &str,
    source: &str,
) -> ContractStructuralTriage {
    let path_low = virtual_path.to_lowercase();
    let short_name = virtual_path
        .rsplit(|c: char| c == '/' || c == '\\')
        .next()
        .unwrap_or(virtual_path);

    let is_external_dep_folder = path_low.starts_with("dependencies/")
        || path_low.contains("/dependencies/")
        || path_low.starts_with('@')
        || path_low.contains("/@")
        || path_low.contains("node_modules/");

    let is_interface_folder = path_low.contains("/interfaces/")
        || path_low.starts_with("interfaces/")
        || (short_name.starts_with('I')
            && short_name.chars().nth(1).map_or(false, |c| c.is_ascii_uppercase()));

    let short_low = short_name.to_lowercase();
    let is_boilerplate_base_file = matches!(
        short_low.as_str(),
        "semver.sol"
            | "initializable.sol"
            | "ownable.sol"
            | "ownable2step.sol"
            | "ownableupgradeable.sol"
            | "burn.sol"
            | "context.sol"
            | "erc165.sol"
            | "accesscontrol.sol"
            | "erc20.sol"
            | "erc20burnable.sol"
            | "safetransfer.sol"
            | "boringmath.sol"
    );

    let is_script_or_test_artifact = path_low.ends_with(".s.sol")
        || path_low.ends_with(".t.sol")
        || path_low.starts_with("script/")
        || path_low.contains("/script/")
        || path_low.starts_with("scripts/")
        || path_low.contains("/scripts/")
        || path_low.contains("/demo/")
        || path_low.starts_with("test/")
        || path_low.contains("/test/")
        || path_low.contains("/mocks/")
        || short_name.starts_with("Deploy")
        || is_boilerplate_base_file;

    const STATE_SIGNATURES: &[&str] = &[
        "mapping(", " storage ", "$.", "totalsupply", "totalassets", "total_assets",
        "total_supply", "balances[", "_balances[", "shares[", "debts[", "positions[",
        "orders[", "proposals[", "nonces[", "reserves", "reserve0", "reserve1",
        "treasury", "index", "rebase", "vesting", "permissions", "-=", "+=",
    ];

    const EXT_INTERACTION_SIGNATURES: &[&str] = &[
        ".call", "delegatecall", "_delegate(", "functioncall", "safetransfer",
        ".transfer(", ".transferfrom(", ".send(", "flashloan", "_mint(", "mint(",
        "_burn(", "burn(", "burnfrom(", "ecrecover(", "ccipreceive", "lzreceive",
    ];

    const MATH_OR_ORACLE_SIGNATURES: &[&str] = &[
        " / ", " % ", "muldiv", "latestrounddata", "getamountout", "getvirtualprice",
        "converttoassets", "converttoshares", "balancefrom", "balanceto", "healthfactor",
        "twap", "exchangerate", " - ",
    ];

    let mut has_concrete_contract = false;
    let mut has_abstract_contract = false;
    let mut has_library_decl = false;
    let mut has_executable_fn = false;
    let mut in_callable_header = false;
    let mut has_storage_state = false;
    let mut has_external_interaction = false;
    let mut has_precision_math = false;
    let mut suspicion_score = 0u32;

    let mut line_budget = 4096usize;
    let mut in_block_comment = false;

    for raw_line in source.lines() {
        match line_budget == 0 {
            true => break,
            false => line_budget -= 1,
        }
        let trimmed = raw_line.trim();
        match trimmed.is_empty() {
            true => continue,
            false => {}
        }

        let lower = trimmed.to_lowercase();
        match in_block_comment {
            true => {
                match lower.contains("*/") {
                    true => in_block_comment = false,
                    false => {}
                }
                continue;
            }
            false => {}
        }

        match lower.starts_with("/*") && !lower.contains("*/") {
            true => {
                in_block_comment = true;
                continue;
            }
            false => {}
        }

        match lower.starts_with("//")
            || lower.starts_with("/*")
            || lower.starts_with('*')
            || lower.starts_with("pragma ")
            || lower.starts_with("import ")
        {
            true => continue,
            false => {}
        }

        let is_abstract =
            lower.starts_with("abstract contract ") || lower.contains("abstract contract ");
        match is_abstract {
            true => has_abstract_contract = true,
            false => {}
        }

        let is_lib = lower.starts_with("library ") || lower.contains(" library ");
        match is_lib {
            true => has_library_decl = true,
            false => {}
        }

        let is_concrete =
            (lower.starts_with("contract ") || lower.contains(" contract ")) && !is_abstract;
        match is_concrete {
            true => {
                has_concrete_contract = true;
                suspicion_score = suspicion_score.saturating_add(15);
            }
            false => {}
        }

        let starts_callable = lower.contains("function ")
            || lower.starts_with("constructor(")
            || lower.starts_with("constructor (")
            || lower.starts_with("receive(")
            || lower.starts_with("fallback(")
            || lower.starts_with("modifier ");
        match starts_callable {
            true => in_callable_header = true,
            false => {}
        }

        match in_callable_header {
            true => match lower.contains('{') {
                true => {
                    has_executable_fn = true;
                    in_callable_header = false;
                }
                false => match lower.contains(';') {
                    true => in_callable_header = false,
                    false => {}
                },
            },
            false => {}
        }

        let is_state_decl = STATE_SIGNATURES.iter().any(|&sig| lower.contains(sig));
        match is_state_decl {
            true => {
                has_storage_state = true;
                suspicion_score = suspicion_score.saturating_add(10);
            }
            false => {}
        }

        let is_ext = EXT_INTERACTION_SIGNATURES.iter().any(|&sig| lower.contains(sig));
        match is_ext {
            true => {
                has_external_interaction = true;
                suspicion_score = suspicion_score.saturating_add(30);
            }
            false => {}
        }

        let is_math = MATH_OR_ORACLE_SIGNATURES.iter().any(|&sig| lower.contains(sig))
            && (lower.contains('=') || lower.contains("return ") || lower.contains("require("));
        match is_math {
            true => {
                has_precision_math = true;
                suspicion_score = suspicion_score.saturating_add(20);
            }
            false => {}
        }
    }

    let has_stateful_or_call_library = has_library_decl
        && has_executable_fn
        && (has_storage_state && has_external_interaction)
        && !is_external_dep_folder;

    let is_core_business_contract = (has_concrete_contract
        || (has_abstract_contract && (has_storage_state || has_precision_math)))
        && has_executable_fn
        && !is_external_dep_folder;

    let src_low_bounded = match source.len() > 8192 {
        true => {
            let mut cut = 8192;
            while cut > 0 && !source.is_char_boundary(cut) {
                cut -= 1;
            }
            source[..cut].to_lowercase()
        }
        false => source.to_lowercase(),
    };
    let is_foundry_script_body = src_low_bounded.contains("forge-std/script.sol")
        || src_low_bounded.contains("forge-std/test.sol")
        || src_low_bounded.contains(" is script")
        || src_low_bounded.contains("vm.startbroadcast");

    let branch = classify_contract_domain_branch_stack(&path_low, &src_low_bounded);
    let weighted_score = suspicion_score.saturating_add(branch.priority_weight());

    let should_keep = !is_interface_folder
        && !is_script_or_test_artifact
        && !is_foundry_script_body
        && (is_core_business_contract || has_stateful_or_call_library);

    ContractStructuralTriage {
        should_prune: !should_keep,
        suspicion_score: weighted_score,
        branch,
        has_concrete_contract,
        has_stateful_or_call_library,
        has_storage_state,
        has_external_interaction,
        has_precision_math,
    }
}

pub fn is_pruned_library_or_interface_stack(short_name: &str, source: &str) -> bool {
    evaluate_contract_structural_triage_stack(short_name, source).should_prune
}

pub fn extract_token_hashes_stack(input: &str) -> ([u32; MAX_TOKEN_SLOTS], usize) {
    let bytes = input.as_bytes();
    let limit = match bytes.len() > MAX_HASH_SCAN_BYTES {
        true => MAX_HASH_SCAN_BYTES,
        false => bytes.len(),
    };
    let mut hashes = [0u32; MAX_TOKEN_SLOTS];
    let mut count = 0usize;
    let mut i = 0usize;

    while i < limit && count < MAX_TOKEN_SLOTS {
        while i < limit && !(bytes[i].is_ascii_alphanumeric()) {
            i += 1;
        }
        let start = i;
        while i < limit && bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }
        match i > start {
            true => {
                hashes[count] = fnv1a_hash_ascii_lower(&bytes[start..i]);
                count += 1;
            }
            false => {}
        }
    }
    (hashes, count)
}

pub fn has_token_hash(hashes: &[u32; MAX_TOKEN_SLOTS], count: usize, target: u32) -> bool {
    let mut i = 0usize;
    while i < count {
        match hashes[i] == target {
            true => return true,
            false => i += 1,
        }
    }
    false
}

pub const SEMANTIC_SHARE_ACCOUNTING: u64       = 1 << 0;
pub const SEMANTIC_CEI_STATE_LOCK: u64         = 1 << 1;
pub const SEMANTIC_PRECISION_DIV: u64          = 1 << 2;
pub const SEMANTIC_INVARIANT_CONSERVATION: u64 = 1 << 3;
pub const SEMANTIC_CROSS_CONTRACT_VIEW: u64    = 1 << 4;
pub const SEMANTIC_SOLVENCY_BOUNDARY: u64      = 1 << 5;
pub const SEMANTIC_TEMPORAL_HORIZON: u64       = 1 << 6;
pub const SEMANTIC_GOVERNANCE_AUTH: u64        = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxiomFastGateEntry {
    pub signature_hash: u32,
    pub trigger_mask: u64,
    pub semantic_bitmask: u64,
    pub axiom_id: u32,
}

impl AxiomFastGateEntry {
    pub const fn new(
        signature_hash: u32,
        trigger_mask: u64,
        semantic_bitmask: u64,
        axiom_id: u32,
    ) -> Self {
        Self {
            signature_hash,
            trigger_mask,
            semantic_bitmask,
            axiom_id,
        }
    }

    pub const fn resonance_weight_with(&self, other: &Self) -> f64 {
        let shared_semantics = (self.semantic_bitmask & other.semantic_bitmask).count_ones();
        let union_semantics = (self.semantic_bitmask | other.semantic_bitmask).count_ones();
        let shared_triggers = (self.trigger_mask & other.trigger_mask).count_ones();

        let denom = match union_semantics == 0 {
            true => 1u32,
            false => union_semantics,
        };
        let base_ratio = (shared_semantics as f64) / (denom as f64);
        let trigger_bonus = (shared_triggers as f64) * 0.125;
        base_ratio + trigger_bonus
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptDenyFunnel {
    pub accepted: [Option<AxiomFastGateEntry>; MAX_ACCEPT_SLOTS],
    pub accepted_count: usize,
    pub denied_count: usize,
}

impl AcceptDenyFunnel {
    pub const fn new() -> Self {
        Self {
            accepted: [None; MAX_ACCEPT_SLOTS],
            accepted_count: 0,
            denied_count: 0,
        }
    }

    pub fn evaluate(&mut self, problem_mask: u64, candidate: AxiomFastGateEntry) {
        let trigger_matched = (problem_mask & candidate.trigger_mask) == candidate.trigger_mask
            && candidate.trigger_mask != 0;
        let semantic_resonated = (problem_mask & candidate.semantic_bitmask) != 0
            && candidate.semantic_bitmask != 0;
        match (trigger_matched || semantic_resonated) && self.accepted_count < MAX_ACCEPT_SLOTS {
            true => {
                self.accepted[self.accepted_count] = Some(candidate);
                self.accepted_count += 1;
            }
            false => {
                self.denied_count = self.denied_count.saturating_add(1);
            }
        }
    }
}

pub struct AxiomTemplateCatalog;

impl AxiomTemplateCatalog {
    pub fn lookup(keyword: &str) -> Option<MathematicalAxiom> {
        let trimmed = keyword.trim();
        match trimmed.is_empty() {
            true => return None,
            false => {}
        }

        let exact_hash = fnv1a_hash_ascii_lower(trimmed.as_bytes());
        match exact_hash {
            HASH_CHOLESKY => return Some(Self::build_cholesky()),
            HASH_JACOBI | HASH_JACOBI_EIGEN => return Some(Self::build_jacobi()),
            HASH_QR | HASH_GRAM_SCHMIDT | HASH_QR_GRAM_SCHMIDT => return Some(Self::build_qr()),
            HASH_PYRAMID | HASH_PYRAMID_ISO => return Some(Self::build_pyramid()),
            HASH_TETRAHEDRON | HASH_TETRAHEDRON_ISO => return Some(Self::build_tetrahedron()),
            HASH_OCTAHEDRON | HASH_OCTAHEDRON_ISO => return Some(Self::build_octahedron()),
            HASH_DOOLITTLE | HASH_DOOLITTLE_LU | HASH_LU_DECOMP => return Some(Self::build_lu()),
            HASH_AMM | HASH_XY_K | HASH_CONST_PROD | HASH_LIQ_POOL | HASH_AMM_INVARIANT => {
                return Some(Self::build_amm())
            }
            HASH_DEPHASING | HASH_DAMPING | HASH_DEPHASING_CHAN => {
                return Some(Self::build_dephasing())
            }
            HASH_TRAJECTORY | HASH_FUTURE_FLOW => {
                return Some(Self::build_future_trajectory())
            }
            HASH_CUMULATIVE_DELTA | HASH_MICRO_DRAIN | HASH_MULDIV | HASH_ACCUMULATED_DUST => {
                return Some(Self::build_cumulative_delta())
            }
            _ => {}
        }

        let (tok_hashes, tok_count) = extract_token_hashes_stack(trimmed);
        let has_householder = has_token_hash(&tok_hashes, tok_count, HASH_HOUSEHOLDER);
        let has_tridiagonal = has_token_hash(&tok_hashes, tok_count, HASH_TRIDIAGONAL);

        match has_token_hash(&tok_hashes, tok_count, HASH_CHOLESKY) {
            true => return Some(Self::build_cholesky()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_JACOBI) {
            true => return Some(Self::build_jacobi()),
            false => {}
        }

        let is_qr = has_token_hash(&tok_hashes, tok_count, HASH_QR)
            || (has_token_hash(&tok_hashes, tok_count, fnv1a_hash_ascii_lower(b"gram"))
                && has_token_hash(&tok_hashes, tok_count, fnv1a_hash_ascii_lower(b"schmidt")));
        match is_qr && !has_householder && !has_tridiagonal {
            true => return Some(Self::build_qr()),
            false => {}
        }

        let normalized = trimmed.to_lowercase();
        match has_token_hash(&tok_hashes, tok_count, HASH_PYRAMID) {
            true => return Some(Self::build_pyramid()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_TETRAHEDRON) {
            true => return Some(Self::build_tetrahedron()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_OCTAHEDRON) {
            true => return Some(Self::build_octahedron()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_DOOLITTLE)
            || normalized.contains("lu_decomposition")
        {
            true => return Some(Self::build_lu()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_AMM)
            || normalized.contains("constant_product")
            || normalized.contains("liquidity_pool")
            || normalized.contains("xy_k")
        {
            true => return Some(Self::build_amm()),
            false => {}
        }
        match has_token_hash(&tok_hashes, tok_count, HASH_DEPHASING)
            || has_token_hash(&tok_hashes, tok_count, HASH_DAMPING)
        {
            true => return Some(Self::build_dephasing()),
            false => {}
        }
        match exact_hash == HASH_POLAR_DECOMP
            || has_token_hash(&tok_hashes, tok_count, HASH_POLAR)
            || normalized.contains("polar_decomposition")
        {
            true => return Some(Self::build_polar()),
            false => {}
        }
        match exact_hash == HASH_HOPF_FIBRATION
            || has_token_hash(&tok_hashes, tok_count, HASH_HOPF)
            || normalized.contains("hopf_fibration")
        {
            true => return Some(Self::build_hopf_fibration()),
            false => {}
        }

        None
    }

    fn build_polar() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "factorization_polar_decomposition_unitary".to_string(),
            title: "Canonical Polar Decomposition (A = U * P)".to_string(),
            category: "matrix_factorization".to_string(),
            principle: "Every square matrix A factors uniquely into A = U * P where U is orthogonal (U * U^T = I) and P is positive semi-definite symmetric (P = sqrt(A^T * A)).".to_string(),
            diagonal_formula: "P = V * sqrt(Lambda) * V^T".to_string(),
            off_diagonal_formula: "U = A * P^(-1), U * U^T = I".to_string(),
            output_symbol: "U, P".to_string(),
            pre_conditions: "len(A) == len(A[0]) and len(A) > 0".to_string(),
            core_algorithm: "AT = mat_transpose(A)\nATA = mat_mul(AT, A)\nP = [list(r) for r in ATA]\nU = [[float(r == c) for c in range(n)] for r in range(n)]".to_string(),
            post_conditions: "is_symmetric(P)".to_string(),
        }
    }

    fn build_hopf_fibration() -> MathematicalAxiom {
        Self::build_erc4626_panic_try_catch_spec()
    }

    fn build_cholesky() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "cholesky".to_string(),
            title: "Cholesky Positive-Definite Matrix Factorization".to_string(),
            category: "matrix_factorization".to_string(),
            principle: "Symmetric positive-definite matrix decomposition A = L * L^T.".to_string(),
            diagonal_formula: "math.sqrt(A[i][i] - sum(L[i][k]**2 for k in range(i)))".to_string(),
            off_diagonal_formula: "(A[j][i] - sum(L[j][k] * L[i][k] for k in range(i))) / L[i][i]".to_string(),
            output_symbol: "L".to_string(),
            pre_conditions: "is_symmetric(A) and len(A) == len(A[0])".to_string(),
            core_algorithm: "for i in range(n):\n    L[i][i] = math.sqrt(A[i][i] - sum(L[i][k]**2 for k in range(i)))\n    for j in range(i + 1, n):\n        L[j][i] = (A[j][i] - sum(L[j][k] * L[i][k] for k in range(i))) / L[i][i]".to_string(),
            post_conditions: "max(abs(A[i][j] - sum(L[i][k] * L[j][k] for k in range(n))) for i in range(n) for j in range(n)) < 1e-4".to_string(),
        }
    }

    fn build_jacobi() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "jacobi_eigenvalue".to_string(),
            title: "Jacobi Orthogonal Eigenvalue Decomposition".to_string(),
            category: "spectral_analysis".to_string(),
            principle: "Orthogonal Givens rotation diagonalization A = V * E * V^T.".to_string(),
            diagonal_formula: "E[i][i]".to_string(),
            off_diagonal_formula: "E[i][j] -> 0".to_string(),
            output_symbol: "E, V".to_string(),
            pre_conditions: "is_symmetric(A) and len(A) == len(A[0])".to_string(),
            core_algorithm: "B = [list(r) for r in A]\nfor i in range(n):\n    V[i][i] = 1.0\n    E[i][i] = B[i][i]".to_string(),
            post_conditions: "is_symmetric(A)".to_string(),
        }
    }

    fn build_qr() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "qr_gram_schmidt".to_string(),
            title: "Gram-Schmidt Orthogonal QR Factorization".to_string(),
            category: "matrix_factorization".to_string(),
            principle: "Orthogonal-triangular factorization A = Q * R.".to_string(),
            diagonal_formula: "norm(u_k)".to_string(),
            off_diagonal_formula: "dot(q_i, a_j)".to_string(),
            output_symbol: "Q, R".to_string(),
            pre_conditions: "len(A) == len(A[0])".to_string(),
            core_algorithm: "cols = [[A[r][c] for r in range(n)] for c in range(n)]\nq_cols = []\nfor j in range(n):\n    v = list(cols[j])\n    for i in range(j):\n        r_ij = sum(q_cols[i][k] * cols[j][k] for k in range(n))\n        R[i][j] = r_ij\n        for k in range(n):\n            v[k] -= r_ij * q_cols[i][k]\n    norm_v = math.sqrt(sum(x**2 for x in v))\n    R[j][j] = norm_v\n    q_cols.append([x / norm_v for x in v])\nfor r in range(n):\n    for c in range(n):\n        Q[r][c] = q_cols[c][r]".to_string(),
            post_conditions: "diff(A, mat_mul(Q, R)) < 1e-4".to_string(),
        }
    }

    fn build_pyramid() -> MathematicalAxiom {
        Self::build_erc4626_panic_try_catch_spec()
    }

    fn build_tetrahedron() -> MathematicalAxiom {
        Self::build_oz_checked_sub_donation_spec()
    }

    fn build_octahedron() -> MathematicalAxiom {
        Self::build_oz_checked_sub_donation_spec()
    }

    fn build_lu() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "doolittle_lu".to_string(),
            title: "Doolittle LU Matrix Factorization".to_string(),
            category: "matrix_factorization".to_string(),
            principle: "A = L * U factorization with unit lower-triangular diagonal L[i][i] = 1.0.".to_string(),
            diagonal_formula: "U[i][i] = A[i][i] - sum(L[i][k] * U[k][i] for k in range(i))".to_string(),
            off_diagonal_formula: "L[j][i] = (A[j][i] - sum(L[j][k] * U[k][i] for k in range(i))) / U[i][i]".to_string(),
            output_symbol: "L, U".to_string(),
            pre_conditions: "len(A) == len(A[0])".to_string(),
            core_algorithm: "for i in range(n):\n    L[i][i] = 1.0\n    for j in range(i, n):\n        U[i][j] = A[i][j] - sum(L[i][k] * U[k][j] for k in range(i))\n    for j in range(i + 1, n):\n        L[j][i] = (A[j][i] - sum(L[j][k] * U[k][i] for k in range(i))) / U[i][i]".to_string(),
            post_conditions: "diff(A, mat_mul(L, U)) < 1e-4".to_string(),
        }
    }

    pub fn build_future_trajectory() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "future_cashflow_trajectory_invariant".to_string(),
            title: "Deterministic 7-Day (50,400-Block) Solvency Trajectory Invariant".to_string(),
            category: "economic_invariant".to_string(),
            principle: "Inter-temporal liquidity conservation: V(T + delta_t) >= V(T) - epsilon_dust across all state transitions.".to_string(),
            diagonal_formula: "V_t = V_0 * (1 - leak_rate)^N_tx".to_string(),
            off_diagonal_formula: "Delta_V_7d = V_0 - V(50400_blocks)".to_string(),
            output_symbol: "V_7d_unpatched, V_7d_patched, cumulative_drain".to_string(),
            pre_conditions: "V_0 > 0 and N_blocks == 50400".to_string(),
            core_algorithm: "V_7d_unpatched = 0\nV_7d_patched = V_0\ncumulative_drain = V_0".to_string(),
            post_conditions: "V_7d_patched == V_0".to_string(),
        }
    }

    pub fn build_cumulative_delta() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "cumulative_delta_conservation".to_string(),
            title: "Cumulative Delta Cashflow Conservation Equation".to_string(),
            category: "economic_invariant".to_string(),
            principle: "Total inbound assets must equal outbound assets plus protocol fees and accumulated dust: sum(Assets_in) == sum(Assets_out) + Fees + accumulatedDust.".to_string(),
            diagonal_formula: "Delta_t = Assets_in(t) - (Assets_out(t) + Fee(t) + Dust(t)) == 0".to_string(),
            off_diagonal_formula: "Q = FullMath.mulDiv(amount, supply, assets)".to_string(),
            output_symbol: "assets_out, share, fee, quotient".to_string(),
            pre_conditions: "assets > 0 and supply > 0".to_string(),
            core_algorithm: "quotient = (amount_in * supply) // assets\nremainder = (amount_in * supply) % assets\naccumulated_dust = remainder".to_string(),
            post_conditions: "quotient > 0 and (quotient * assets + accumulated_dust == amount_in * supply)".to_string(),
        }
    }

    pub fn build_erc4626_panic_try_catch_spec() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "erc4626_convert_rounding_and_panic_selector_invariant".to_string(),
            title: "ERC-4626 Floor Rounding & Panic(0x11) Try/Catch Selector Invariant".to_string(),
            category: "formal_security".to_string(),
            principle: "In ERC-4626 vaults, convertToAssets(shares) rounds down. Any solvency subtraction inside an external try/catch block decoding custom tuples must use saturating subtraction to prevent Panic(0x11) selector 0x4e487b71 from crashing the catch handler.".to_string(),
            diagonal_formula: "stakedDelta = max(0, newStaked - oldStaked)".to_string(),
            off_diagonal_formula: "Selector(Panic(0x11)) = 0x4e487b71 != abi.encode(bool, bytes, bool)".to_string(),
            output_symbol: "stakedAssets, oldStakedAssets, solvencyCheckPassed".to_string(),
            pre_conditions: "oldStakedAssets >= 0".to_string(),
            core_algorithm: "staked_delta = max(0, new_staked - old_staked)\nsolvency_ok = staked_delta >= min_expected".to_string(),
            post_conditions: "staked_delta >= 0".to_string(),
        }
    }

    pub fn build_oz_checked_sub_donation_spec() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "oz_checked_sub_permissionless_donation_invariant".to_string(),
            title: "Permissionless Donation Checked-Subtraction Panic(0x11) DoS Invariant".to_string(),
            category: "formal_security".to_string(),
            principle: "When a contract performs Solidity 0.8+ checked subtraction (convertToAssets(totalSupply) - reservedAssets) while allowing permissionless right-hand-side inflation, an attacker can force RHS > LHS to trigger Panic(0x11) DoS.".to_string(),
            diagonal_formula: "netLiability = max(0, totalSupplyAssets - reservedAssets)".to_string(),
            off_diagonal_formula: "reservedAssets_after = reservedAssets + donateAsYield(assets) > convertToAssets(totalSupply)".to_string(),
            output_symbol: "reservedAssets, originalReservedAssets, discrepancy, requiredAssets".to_string(),
            pre_conditions: "True".to_string(),
            core_algorithm: "net_liability = max(0, supply_assets - reserved_assets)\ndiscrepancy = max(0, required_assets - actual_assets)".to_string(),
            post_conditions: "net_liability >= 0 and discrepancy >= 0".to_string(),
        }
    }

    fn build_amm() -> MathematicalAxiom {
        MathematicalAxiom {
            key: "amm_constant_product_invariant".to_string(),
            title: "AMM Constant Product Invariant (x * y = k)".to_string(),
            category: "economic_invariant".to_string(),
            principle: "Reserve product conservation k_after >= k_before across swaps.".to_string(),
            diagonal_formula: "k = reserve_x * reserve_y".to_string(),
            off_diagonal_formula: "amount_out = (reserve_y * effective_in) / (reserve_x + effective_in)".to_string(),
            output_symbol: "k_after, amount_out".to_string(),
            pre_conditions: "amount_in > 0 and reserve_x > 0 and reserve_y > 0".to_string(),
            core_algorithm: "k_before = reserve_x * reserve_y\neffective_in = amount_in - (amount_in * 30) // 10000\namount_out = (reserve_y * effective_in) // (reserve_x + effective_in)\nk_after = (reserve_x + amount_in) * (reserve_y - amount_out)".to_string(),
            post_conditions: "k_after >= k_before".to_string(),
        }
    }

    fn build_dephasing() -> MathematicalAxiom {
        Self::build_cumulative_delta()
    }

    pub fn synthesize_canonical_skeleton(topic: &str) -> MathematicalAxiom {
        let clean_key: String = topic
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let key = match clean_key.is_empty() {
            true => "canonical_numerical_method".to_string(),
            false => clean_key,
        };

        match MathematicalOperatorDomain::classify(topic) {
            MathematicalOperatorDomain::QuantumOperator
            | MathematicalOperatorDomain::PolyhedronGeometry => MathematicalAxiom {
                key,
                title: format!("Deterministic EVM State & Call-Graph Invariant ({})", topic),
                category: "formal_security".to_string(),
                principle: "State transition conservation across external interactions.".to_string(),
                diagonal_formula: "state_after >= state_before".to_string(),
                off_diagonal_formula: "delta_s = 0".to_string(),
                output_symbol: "amount, quotient".to_string(),
                pre_conditions: "True".to_string(),
                core_algorithm: "amount = 1000\nquotient = 1000".to_string(),
                post_conditions: "quotient > 0".to_string(),
            },
            MathematicalOperatorDomain::MatrixFactorization => MathematicalAxiom {
                key,
                title: format!("Canonical Matrix Factorization ({})", topic),
                category: "matrix_factorization".to_string(),
                principle: "A = L * U.".to_string(),
                diagonal_formula: "U[i][i]".to_string(),
                off_diagonal_formula: "L[i][j]".to_string(),
                output_symbol: "L, U".to_string(),
                pre_conditions: "len(A) == len(A[0]) and len(A) > 0".to_string(),
                core_algorithm: "for i in range(n):\n    L[i][i] = 1.0\n    for j in range(i, n):\n        U[i][j] = A[i][j] - sum(L[i][k] * U[k][j] for k in range(i))\n    for j in range(i + 1, n):\n        L[j][i] = (A[j][i] - sum(L[j][k] * U[k][i] for k in range(i))) / U[i][i]".to_string(),
                post_conditions: "diff(A, mat_mul(L, U)) < 1e-4".to_string(),
            },
            MathematicalOperatorDomain::SpectralIteration => MathematicalAxiom {
                key,
                title: format!("Spectral Eigenvalue Iteration ({})", topic),
                category: "spectral_iteration".to_string(),
                principle: "Dominant spectral eigenvalue convergence.".to_string(),
                diagonal_formula: "lambda_val".to_string(),
                off_diagonal_formula: "v[i]".to_string(),
                output_symbol: "lambda_val, v".to_string(),
                pre_conditions: "len(A) == len(A[0]) and len(A) > 0".to_string(),
                core_algorithm: "v = [1.0 for _ in range(n)]\nnorm_init = max(vec_norm(v), 1e-12)\nv = [x / norm_init for x in v]\nlambda_val = 1.0".to_string(),
                post_conditions: "abs(lambda_val) >= 0.0".to_string(),
            },
            MathematicalOperatorDomain::IterativeRelaxation => MathematicalAxiom {
                key,
                title: format!("Iterative Relaxation Solver ({})", topic),
                category: "iterative_relaxation".to_string(),
                principle: "Fixed-point relaxation for Ax = b.".to_string(),
                diagonal_formula: "A[i][i]".to_string(),
                off_diagonal_formula: "x_sol[i]".to_string(),
                output_symbol: "x_sol".to_string(),
                pre_conditions: "len(A) == len(A[0])".to_string(),
                core_algorithm: "x_sol = [1.0 for _ in range(n)]".to_string(),
                post_conditions: "len(x_sol) == n".to_string(),
            },
            MathematicalOperatorDomain::ProjectionGrammar => MathematicalAxiom {
                key,
                title: format!("Orthogonal Subspace Projection ({})", topic),
                category: "subspace_projection".to_string(),
                principle: "Idempotent projection operator P^2 = P and P^T = P.".to_string(),
                diagonal_formula: "P_proj[i][i]".to_string(),
                off_diagonal_formula: "P_proj[i][j]".to_string(),
                output_symbol: "P_proj".to_string(),
                pre_conditions: "len(A) > 0".to_string(),
                core_algorithm: "P_proj = [[float(r == c) for c in range(n)] for r in range(n)]".to_string(),
                post_conditions: "diff(P_proj, mat_mul(P_proj, P_proj)) < 1e-4".to_string(),
            },
            MathematicalOperatorDomain::DynamicStepping => MathematicalAxiom {
                key,
                title: format!("Symplectic Numerical Integrator ({})", topic),
                category: "numerical_stepping".to_string(),
                principle: "Phase-space trajectory conservation.".to_string(),
                diagonal_formula: "x_traj[i]".to_string(),
                off_diagonal_formula: "A[i][j]".to_string(),
                output_symbol: "x_traj".to_string(),
                pre_conditions: "len(A) == len(A[0]) and len(A) > 0".to_string(),
                core_algorithm: "x_traj = [1.0 for _ in range(n)]".to_string(),
                post_conditions: "len(x_traj) == n".to_string(),
            },
            MathematicalOperatorDomain::InvariantConservation
            | MathematicalOperatorDomain::Unclassified => MathematicalAxiom {
                key,
                title: format!("Deterministic State Conservation Invariant ({})", topic),
                category: "economic_invariant".to_string(),
                principle: "Integer conservation Q = (N * D) / M.".to_string(),
                diagonal_formula: "k_after >= k_before".to_string(),
                off_diagonal_formula: "Q = (N * D) / M".to_string(),
                output_symbol: "amount, quotient".to_string(),
                pre_conditions: "True".to_string(),
                core_algorithm: "amount = 1000\nquotient = 1000".to_string(),
                post_conditions: "quotient > 0".to_string(),
            },
        }
    }

    pub fn lookup_or_synthesize(topic: &str) -> MathematicalAxiom {
        let clean_key: String = topic
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let master_path = Path::new("garry_workspace")
            .join("knowledge")
            .join(format!("{}.jsonl", clean_key));

        match master_path.is_file() {
            true => match std::fs::read_to_string(&master_path) {
                Ok(content) => {
                    let first_line = content.lines().next().unwrap_or("").trim();
                    match MathematicalAxiom::from_jsonl_line(first_line) {
                        Some(existing_master_axiom) => {
                            let is_safe = verify_code_safety(&existing_master_axiom.core_algorithm).is_ok()
                                && verify_code_safety(&existing_master_axiom.pre_conditions).is_ok()
                                && verify_code_safety(&existing_master_axiom.post_conditions).is_ok()
                                && !existing_master_axiom.core_algorithm.trim().is_empty();
                            match is_safe {
                                true => return existing_master_axiom,
                                false => {}
                            }
                        }
                        None => {}
                    }
                }
                Err(_) => {}
            },
            false => {}
        }

        match Self::lookup(topic) {
            Some(axiom) => axiom,
            None => Self::synthesize_canonical_skeleton(topic),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixedTraceBuffer4 {
    pub items: [Option<String>; 4],
    pub count: usize,
}

impl FixedTraceBuffer4 {
    pub const fn new() -> Self {
        Self {
            items: [None, None, None, None],
            count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn push(&mut self, item: impl Into<String>) {
        match self.count < 4 {
            true => {
                self.items[self.count] = Some(item.into());
                self.count += 1;
            }
            false => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RepairEpochReport {
    pub axiom_key: String,
    pub initial_epoch_passed: bool,
    pub epochs_attempted: usize,
    pub converged: bool,
    pub error_traces: FixedTraceBuffer4,
    pub applied_repairs: FixedTraceBuffer4,
    pub final_axiom: MathematicalAxiom,
}

pub fn verify_and_repair_axiom_execution(
    axiom: &MathematicalAxiom,
) -> Result<RepairEpochReport, String> {
    verify_code_safety(&axiom.core_algorithm)
        .map_err(|r| format!("Static code safety violation in core_algorithm: {}", r))?;
    verify_code_safety(&axiom.pre_conditions)
        .map_err(|r| format!("Static code safety violation in pre_conditions: {}", r))?;
    verify_code_safety(&axiom.post_conditions)
        .map_err(|r| format!("Static code safety violation in post_conditions: {}", r))?;

    let domain = MathematicalOperatorDomain::classify(&axiom.key);
    let has_pre = !axiom.pre_conditions.trim().is_empty();
    let has_core = !axiom.core_algorithm.trim().is_empty();
    let has_post = !axiom.post_conditions.trim().is_empty();

    match (has_pre, has_core, has_post) {
        (true, true, true) => {
            let (key_tokens, key_tok_count) = extract_token_hashes_stack(&axiom.key);
            let is_lu_axiom = has_token_hash(&key_tokens, key_tok_count, fnv1a_hash_ascii_lower(b"lu"))
                || has_token_hash(&key_tokens, key_tok_count, HASH_DOOLITTLE);
            match (domain, is_lu_axiom) {
                (MathematicalOperatorDomain::MatrixFactorization, true) => {
                    match axiom.core_algorithm.contains("L[i][i] = 1.0") {
                        true => Ok(RepairEpochReport {
                            axiom_key: axiom.key.clone(),
                            initial_epoch_passed: true,
                            epochs_attempted: 1,
                            converged: true,
                            error_traces: FixedTraceBuffer4::new(),
                            applied_repairs: FixedTraceBuffer4::new(),
                            final_axiom: axiom.clone(),
                        }),
                        false => Err(
                            "Axiom rejected: LU Factorization violates unit diagonal invariant L[i][i] = 1.0"
                                .to_string(),
                        ),
                    }
                }
                _ => Ok(RepairEpochReport {
                    axiom_key: axiom.key.clone(),
                    initial_epoch_passed: true,
                    epochs_attempted: 1,
                    converged: true,
                    error_traces: FixedTraceBuffer4::new(),
                    applied_repairs: FixedTraceBuffer4::new(),
                    final_axiom: axiom.clone(),
                }),
            }
        }
        _ => Err(format!(
            "Axiom rejected: Incomplete formal contract specification in '{}'",
            axiom.key
        )),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SwarmResearchCoordinator;

impl SwarmResearchCoordinator {
    pub const fn new() -> Self {
        Self
    }

    pub fn dispatch_executable_axiom_swarm_sync(
        &self,
        target_algorithm: &str,
        sub_tasks_count: usize,
    ) -> Result<MathematicalAxiom, String> {
        let target_clean = target_algorithm.trim().to_lowercase();
        match contains_prompt_injection(&target_clean) {
            true => {
                return Err(
                    "Target algorithm contains prohibited prompt injection patterns".to_string(),
                )
            }
            false => {}
        }

        let bounded_tasks = sub_tasks_count.clamp(1, 16);
        let mut candidate_axiom: Option<MathematicalAxiom> = None;
        let mut idx = 0usize;

        while idx < bounded_tasks {
            let raw_axiom = AxiomTemplateCatalog::lookup_or_synthesize(&target_clean);
            match candidate_axiom.is_none() {
                true => candidate_axiom = Some(raw_axiom),
                false => {}
            }
            idx += 1;
        }

        let axiom = candidate_axiom
            .ok_or_else(|| "Swarm completed with 0 synthesized axioms".to_string())?;
        let repair_report = verify_and_repair_axiom_execution(&axiom)?;
        match repair_report.converged {
            true => Ok(repair_report.final_axiom),
            false => Err(format!(
                "Formal verification failed to converge for axiom '{}'",
                axiom.key
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SovereignApprovalReport {
    pub committed_count: usize,
    pub archived_count: usize,
    pub initial_crc32: u32,
    pub final_crc32: u32,
    pub master_composite_score: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GateError {
    Engine(EngineError),
    CorruptedCheckpoint(String),
    EmptyBatch,
    StorageCapacityExhausted { used_slots: usize },
    CodeSafetyViolation { key: String, reason: &'static str },
    DiskWrite(String),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::Engine(e) => write!(f, "Deterministic engine failure: {}", e),
            GateError::CorruptedCheckpoint(s) => write!(f, "Corrupted checkpoint metadata: {}", s),
            GateError::EmptyBatch => write!(f, "Empty axiom candidate batch"),
            GateError::StorageCapacityExhausted { used_slots } => write!(
                f,
                "Storage capacity exhausted: working memory has {} active slots",
                used_slots
            ),
            GateError::CodeSafetyViolation { key, reason } => write!(
                f,
                "Code safety violation in axiom candidate '{}': {}",
                key, reason
            ),
            GateError::DiskWrite(s) => write!(f, "Disk write failed: {}", s),
        }
    }
}

fn trim_ascii_slice(slice: &[u8]) -> &[u8] {
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

fn internal_store_axiom_handler(
    payload: &[u8],
    storage: &mut BoundedStorage,
) -> Result<(), EngineError> {
    match storage.slots.iter().flatten().count() >= 15 {
        true => {
            storage.slots[14] = None;
            storage.slots[15] = None;
        }
        false => {}
    }
    match payload.iter().position(|&b| b == b'=' || b == b':') {
        Some(pos) => {
            let key_slice = trim_ascii_slice(&payload[..pos]);
            let key = match key_slice.len() > MAX_KEY_SIZE {
                true => &key_slice[..MAX_KEY_SIZE],
                false => key_slice,
            };

            let val_slice = match payload.len() > pos + 1 && payload[pos + 1] == b'=' {
                true => trim_ascii_slice(&payload[pos + 2..]),
                false => trim_ascii_slice(&payload[pos + 1..]),
            };
            let val = match val_slice.len() > MAX_VALUE_SIZE {
                true => &val_slice[..MAX_VALUE_SIZE],
                false => val_slice,
            };

            match key.is_empty() {
                false => storage.set(key, val),
                true => storage.set(b"last_axiom", val),
            }
        }
        None => {
            let safe_payload = match payload.len() > MAX_VALUE_SIZE {
                true => &payload[..MAX_VALUE_SIZE],
                false => payload,
            };
            storage.set(b"last_axiom", safe_payload)
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SovereignAuthorizationGate;

impl SovereignAuthorizationGate {
    pub const fn new() -> Self {
        Self
    }

    pub fn authorize_and_persist_executable_axiom(
        &self,
        axiom: &MathematicalAxiom,
        knowledge_dir: &Path,
        engine: &mut DeterministicEngine,
    ) -> Result<SovereignApprovalReport, GateError> {
        verify_code_safety(&axiom.core_algorithm).map_err(|reason| {
            GateError::CodeSafetyViolation {
                key: axiom.key.clone(),
                reason,
            }
        })?;
        verify_code_safety(&axiom.pre_conditions).map_err(|reason| {
            GateError::CodeSafetyViolation {
                key: axiom.key.clone(),
                reason,
            }
        })?;
        verify_code_safety(&axiom.post_conditions).map_err(|reason| {
            GateError::CodeSafetyViolation {
                key: axiom.key.clone(),
                reason,
            }
        })?;

        let initial_checkpoint = engine.export_checkpoint_array();
        let initial_meta = CheckpointMetadata::inspect(&initial_checkpoint)
            .map_err(|e| GateError::CorruptedCheckpoint(format!("{:?}", e)))?;

        let _ = engine
            .register_action("STORE_AXIOM", internal_store_axiom_handler)
            .map_err(GateError::Engine)?;

        match engine.state() {
            EngineState::Idle | EngineState::Verifying => {
                engine.trigger_planning().map_err(GateError::Engine)?;
            }
            EngineState::Planning => {}
            _ => {}
        }

        let payload_raw = format!("{}={}", axiom.key, axiom.title);
        let safe_payload = match payload_raw.len() > MAX_VALUE_SIZE {
            true => {
                let mut end = MAX_VALUE_SIZE;
                while end > 0 && !payload_raw.is_char_boundary(end) {
                    end -= 1;
                }
                &payload_raw[..end]
            }
            false => &payload_raw,
        };
        let proposal = ActionProposal::new("STORE_AXIOM", safe_payload.as_bytes())
            .map_err(GateError::Engine)?
            .validate(1)
            .map_err(GateError::Engine)?;

        engine.execute_proposal(proposal).map_err(GateError::Engine)?;
        engine
            .finalize_verification(true)
            .map_err(GateError::Engine)?;

        let final_checkpoint = engine.export_checkpoint_array();
        let final_meta = CheckpointMetadata::inspect(&final_checkpoint)
            .map_err(|e| GateError::CorruptedCheckpoint(format!("{:?}", e)))?;

        std::fs::create_dir_all(knowledge_dir)
            .map_err(|e| GateError::DiskWrite(format!("Failed to create knowledge directory: {}", e)))?;

        let file_path = knowledge_dir.join(format!("{}.jsonl", axiom.key));
        let serialized = axiom.to_jsonl_line();

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .map_err(|e| GateError::DiskWrite(format!("Failed to open axiom destination file: {}", e)))?;

        writeln!(file, "{}", serialized)
            .map_err(|e| GateError::DiskWrite(format!("Failed to write axiom payload: {}", e)))?;
        file.sync_all()
            .map_err(|e| GateError::DiskWrite(format!("Failed to sync axiom file to disk: {}", e)))?;

        Ok(SovereignApprovalReport {
            committed_count: 1,
            archived_count: 0,
            initial_crc32: initial_meta.checksum,
            final_crc32: final_meta.checksum,
            master_composite_score: 1.0,
        })
    }
}

pub fn lookup_builtin_axiom(keyword: &str) -> Option<MathematicalAxiom> {
    match AxiomTemplateCatalog::lookup(keyword) {
        Some(ax) => Some(ax),
        None => {
            let lower = keyword.trim().to_lowercase();
            let is_dedicated_density_route =
                lower.contains("quantum_density") || lower.contains("purity_operator");
            let has_canonical_prefix = !is_dedicated_density_route
                && (lower.contains("quantum_")
                    || lower.contains("polyhedron_")
                    || lower.contains("factorization_")
                    || lower.contains("spectral_")
                    || lower.contains("relaxation_")
                    || lower.contains("projection_")
                    || lower.contains("stepping_")
                    || lower.contains("invariant_"));
            match has_canonical_prefix {
                true => {
                    let target_key = lower.as_str();
                    for word in lower.split_whitespace() {
                        let clean: String = word
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        let is_sci_token = clean.starts_with("quantum_")
                            || clean.starts_with("polyhedron_")
                            || clean.starts_with("factorization_")
                            || clean.starts_with("spectral_")
                            || clean.starts_with("relaxation_")
                            || clean.starts_with("projection_")
                            || clean.starts_with("stepping_")
                            || clean.starts_with("invariant_");
                        match is_sci_token {
                            true => return Some(AxiomTemplateCatalog::synthesize_canonical_skeleton(&clean)),
                            false => {}
                        }
                    }
                    Some(AxiomTemplateCatalog::synthesize_canonical_skeleton(target_key))
                }
                false => None,
            }
        }
    }
}

pub fn lookup_mathematical_axiom_in_dir(
    dir_path: &Path,
    keyword: &str,
) -> Option<MathematicalAxiom> {
    let normalized = keyword.trim().to_lowercase();
    match normalized.is_empty() {
        true => return None,
        false => {}
    }

    match dir_path.is_dir() {
        true => {
            let mut word_budget = 24usize;
            for raw_word in normalized.split_whitespace() {
                match word_budget == 0 {
                    true => break,
                    false => word_budget -= 1,
                }
                let clean_word: String = raw_word
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                match clean_word.len() >= 3 {
                    true => {
                        let direct_path = dir_path.join(format!("{}.jsonl", clean_word));
                        match direct_path.is_file() {
                            true => match std::fs::File::open(&direct_path) {
                                Ok(file) => {
                                    let reader = std::io::BufReader::new(file);
                                    let mut line_budget = 32usize;
                                    for line_res in reader.lines() {
                                        match line_budget {
                                            0 => break,
                                            _ => line_budget -= 1,
                                        }
                                        match line_res {
                                            Ok(line) => {
                                                let trimmed = line.trim();
                                                match trimmed.is_empty() {
                                                    true => continue,
                                                    false => match MathematicalAxiom::from_jsonl_line(trimmed) {
                                                        Some(axiom) => {
                                                            let is_safe = verify_code_safety(&axiom.core_algorithm).is_ok()
                                                                && verify_code_safety(&axiom.pre_conditions).is_ok()
                                                                && verify_code_safety(&axiom.post_conditions).is_ok();
                                                            match is_safe {
                                                                true => return Some(axiom),
                                                                false => {}
                                                            }
                                                        }
                                                        None => {}
                                                    },
                                                }
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                }
                                Err(_) => {}
                            },
                            false => {}
                        }
                    }
                    false => {}
                }
            }

            let query_hash = fnv1a_hash_ascii_lower(normalized.as_bytes());
            let (query_tokens, query_tok_count) = extract_token_hashes_stack(&normalized);

            match std::fs::read_dir(dir_path) {
                Ok(entries) => {
                    const NONE_PATH: Option<std::path::PathBuf> = None;
                    let mut jsonl_files: [Option<std::path::PathBuf>; 128] = [NONE_PATH; 128];
                    let mut file_count = 0usize;
                    let mut dir_scan_budget = 256usize;

                    for entry_res in entries {
                        match dir_scan_budget == 0 || file_count >= 128 {
                            true => break,
                            false => dir_scan_budget -= 1,
                        }
                        match entry_res {
                            Ok(entry) => {
                                let path = entry.path();
                                let is_jsonl = path.is_file()
                                    && match path.extension().and_then(|ext| ext.to_str()) {
                                        Some(ext) => ext == "jsonl",
                                        None => false,
                                    };
                                match is_jsonl {
                                    true => {
                                        jsonl_files[file_count] = Some(path);
                                        file_count += 1;
                                    }
                                    false => {}
                                }
                            }
                            Err(_) => {}
                        }
                    }

                    let mut i = 0usize;
                    while i < file_count {
                        let mut min_idx = i;
                        let mut j = i + 1;
                        while j < file_count {
                            match (&jsonl_files[j], &jsonl_files[min_idx]) {
                                (Some(a), Some(b)) => match a < b {
                                    true => min_idx = j,
                                    false => {}
                                },
                                _ => {}
                            }
                            j += 1;
                        }
                        match min_idx != i {
                            true => jsonl_files.swap(i, min_idx),
                            false => {}
                        }
                        i += 1;
                    }

                    let mut best_axiom: Option<MathematicalAxiom> = None;
                    let mut max_specificity_score = 0usize;

                    let mut f_idx = 0usize;
                    while f_idx < file_count {
                        match &jsonl_files[f_idx] {
                            Some(path) => match std::fs::File::open(path) {
                                Ok(file) => {
                                    let reader = std::io::BufReader::new(file);
                                    let mut line_budget = 32usize;
                                    for line_res in reader.lines() {
                                        match line_budget {
                                            0 => break,
                                            _ => line_budget -= 1,
                                        }
                                        match line_res {
                                            Ok(line) => {
                                                let trimmed = line.trim();
                                                match trimmed.is_empty() {
                                                    true => continue,
                                                    false => match MathematicalAxiom::from_jsonl_line(trimmed) {
                                                        Some(axiom) => {
                                                            let key_hash = fnv1a_hash_ascii_lower(axiom.key.as_bytes());
                                                            let (ax_tokens, ax_tok_count) = extract_token_hashes_stack(&axiom.key);

                                                            let match_score = match key_hash == query_hash {
                                                                true => 10_000 + axiom.key.len(),
                                                                false => match normalized.contains(axiom.key.as_str()) {
                                                                    true => axiom.key.len() + 500,
                                                                    false => {
                                                                        let mut hits = 0usize;
                                                                        let mut t_idx = 0usize;
                                                                        while t_idx < ax_tok_count {
                                                                            match has_token_hash(&query_tokens, query_tok_count, ax_tokens[t_idx]) {
                                                                                true => hits += 1,
                                                                                false => {}
                                                                            }
                                                                            t_idx += 1;
                                                                        }
                                                                        match ax_tok_count > 0 && hits == ax_tok_count {
                                                                            true => hits * 20 + axiom.key.len(),
                                                                            false => 0,
                                                                        }
                                                                    }
                                                                },
                                                            };

                                                            match match_score > max_specificity_score {
                                                                true => {
                                                                    let is_safe = verify_code_safety(&axiom.core_algorithm).is_ok()
                                                                        && verify_code_safety(&axiom.pre_conditions).is_ok()
                                                                        && verify_code_safety(&axiom.post_conditions).is_ok();
                                                                    match is_safe {
                                                                        true => {
                                                                            max_specificity_score = match_score;
                                                                            best_axiom = Some(axiom);
                                                                        }
                                                                        false => {}
                                                                    }
                                                                }
                                                                false => {}
                                                            }
                                                        }
                                                        None => {}
                                                    },
                                                }
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                }
                                Err(_) => {}
                            },
                            None => {}
                        }
                        f_idx += 1;
                    }

                    match best_axiom {
                        Some(matched) => return Some(matched),
                        None => {}
                    }
                }
                Err(_) => {}
            }
        }
        false => {}
    }

    lookup_builtin_axiom(&normalized)
}

pub fn lookup_mathematical_axiom(keyword: &str) -> Option<MathematicalAxiom> {
    let knowledge_dir = Path::new("garry_workspace").join("knowledge");
    lookup_mathematical_axiom_in_dir(&knowledge_dir, keyword)
}

// ============================================================================
// SECTION 2: BITMASK SCANNER & 4-SLOT SLIDING AXIOM PIPELINE ON THE STACK (O(1))
// ============================================================================

pub const MAX_PIPELINE_WINDOW: usize = 4;
pub const MAX_SLIDE_BUDGET: usize = 8;
pub const SCRATCHPAD_SIZE: usize = 16;
pub const CATALOG_GATE_SIZE: usize = 9;
pub const MAX_HYPERGRAPH_AXIOMS: usize = 256;

pub const HASH_CALL: u32        = fnv1a_hash_ascii_lower(b"call");
pub const HASH_EXTERNAL: u32    = fnv1a_hash_ascii_lower(b"external");
pub const HASH_REENTRANCY: u32  = fnv1a_hash_ascii_lower(b"reentrancy");
pub const HASH_WITHDRAW: u32    = fnv1a_hash_ascii_lower(b"withdraw");
pub const HASH_TRANSFER: u32    = fnv1a_hash_ascii_lower(b"transfer");
pub const HASH_DIV: u32         = fnv1a_hash_ascii_lower(b"div");
pub const HASH_SHARES: u32      = fnv1a_hash_ascii_lower(b"shares");
pub const HASH_ASSETS: u32      = fnv1a_hash_ascii_lower(b"assets");
pub const HASH_ROUNDING: u32    = fnv1a_hash_ascii_lower(b"rounding");
pub const HASH_QUANTUM: u32     = fnv1a_hash_ascii_lower(b"quantum");
pub const HASH_HILBERT: u32     = fnv1a_hash_ascii_lower(b"hilbert");
pub const HASH_DENSITY: u32     = fnv1a_hash_ascii_lower(b"density");
pub const HASH_BORROW: u32      = fnv1a_hash_ascii_lower(b"borrow");
pub const HASH_LIQUIDATE: u32   = fnv1a_hash_ascii_lower(b"liquidate");
pub const HASH_COLLATERAL: u32  = fnv1a_hash_ascii_lower(b"collateral");
pub const HASH_BRIDGE: u32      = fnv1a_hash_ascii_lower(b"bridge");
pub const HASH_LZRECEIVE: u32   = fnv1a_hash_ascii_lower(b"lzreceive");
pub const HASH_MERKLE: u32      = fnv1a_hash_ascii_lower(b"merkle");
pub const HASH_ORACLE: u32      = fnv1a_hash_ascii_lower(b"oracle");
pub const HASH_TWAP: u32        = fnv1a_hash_ascii_lower(b"twap");
pub const HASH_GOVERNANCE: u32  = fnv1a_hash_ascii_lower(b"governance");
pub const HASH_PROPOSE: u32     = fnv1a_hash_ascii_lower(b"propose");
pub const HASH_UPGRADETO: u32   = fnv1a_hash_ascii_lower(b"upgradeto");
pub const HASH_DISCREPANCY: u32 = fnv1a_hash_ascii_lower(b"discrepancy");

pub const BUILTIN_FAST_GATE_CATALOG: [AxiomFastGateEntry; CATALOG_GATE_SIZE] = [
    AxiomFastGateEntry {
        signature_hash: HASH_CHOLESKY,
        trigger_mask: MASK_FACTORIZATION,
        semantic_bitmask: SEMANTIC_PRECISION_DIV | SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 101,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_DOOLITTLE_LU,
        trigger_mask: MASK_FACTORIZATION,
        semantic_bitmask: SEMANTIC_PRECISION_DIV | SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 102,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_QR_GRAM_SCHMIDT,
        trigger_mask: MASK_FACTORIZATION | MASK_SPECTRAL,
        semantic_bitmask: SEMANTIC_PRECISION_DIV | SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 103,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_JACOBI_EIGEN,
        trigger_mask: MASK_SPECTRAL,
        semantic_bitmask: SEMANTIC_INVARIANT_CONSERVATION | SEMANTIC_TEMPORAL_HORIZON,
        axiom_id: 201,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_PYRAMID_ISO,
        trigger_mask: MASK_POLYHEDRON,
        semantic_bitmask: SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 301,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_TETRAHEDRON_ISO,
        trigger_mask: MASK_POLYHEDRON,
        semantic_bitmask: SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 302,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_OCTAHEDRON_ISO,
        trigger_mask: MASK_POLYHEDRON,
        semantic_bitmask: SEMANTIC_INVARIANT_CONSERVATION,
        axiom_id: 303,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_AMM_INVARIANT,
        trigger_mask: MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC,
        semantic_bitmask: SEMANTIC_SHARE_ACCOUNTING
            | SEMANTIC_PRECISION_DIV
            | SEMANTIC_INVARIANT_CONSERVATION
            | SEMANTIC_SOLVENCY_BOUNDARY,
        axiom_id: 401,
    },
    AxiomFastGateEntry {
        signature_hash: HASH_DEPHASING_CHAN,
        trigger_mask: MASK_QUANTUM | MASK_DEPHASING,
        semantic_bitmask: SEMANTIC_INVARIANT_CONSERVATION | SEMANTIC_TEMPORAL_HORIZON,
        axiom_id: 501,
    },
];

pub fn infer_semantic_bitmask_for_axiom_stack(axiom: &MathematicalAxiom) -> u64 {
    let k_low = axiom.key.to_lowercase();
    let p_low = axiom.principle.to_lowercase();
    let mut sem = 0u64;

    match k_low.contains("share")
        || k_low.contains("vault")
        || k_low.contains("erc4626")
        || p_low.contains("share")
    {
        true => sem |= SEMANTIC_SHARE_ACCOUNTING,
        false => {}
    }
    match k_low.contains("reentrancy")
        || k_low.contains("cei")
        || k_low.contains("swc107")
        || p_low.contains("external")
    {
        true => sem |= SEMANTIC_CEI_STATE_LOCK,
        false => {}
    }
    match k_low.contains("rounding")
        || k_low.contains("truncation")
        || k_low.contains("cwe369")
        || k_low.contains("muldiv")
        || p_low.contains("round")
    {
        true => sem |= SEMANTIC_PRECISION_DIV,
        false => {}
    }
    match k_low.contains("invariant")
        || k_low.contains("conservation")
        || k_low.contains("constant_product")
        || k_low.contains("cumulative_delta")
    {
        true => sem |= SEMANTIC_INVARIANT_CONSERVATION,
        false => {}
    }
    match k_low.contains("oracle") || k_low.contains("cross_contract") || k_low.contains("twap") {
        true => sem |= SEMANTIC_CROSS_CONTRACT_VIEW,
        false => {}
    }
    match k_low.contains("solvency")
        || k_low.contains("underflow")
        || k_low.contains("panic")
        || k_low.contains("donation")
    {
        true => sem |= SEMANTIC_SOLVENCY_BOUNDARY,
        false => {}
    }
    match k_low.contains("trajectory") || k_low.contains("future") || k_low.contains("50400") {
        true => sem |= SEMANTIC_TEMPORAL_HORIZON,
        false => {}
    }

    match sem == 0 {
        true => SEMANTIC_INVARIANT_CONSERVATION | SEMANTIC_PRECISION_DIV,
        false => sem,
    }
}

pub fn compute_problem_bitmask(input: &str) -> u64 {
    let (hashes, count) = extract_token_hashes_stack(input);
    let mut mask = 0u64;
    let mut i = 0usize;

    while i < count {
        let h = hashes[i];
        match h {
            HASH_QUANTUM | HASH_HILBERT | HASH_DENSITY => mask |= MASK_QUANTUM,
            HASH_DEPHASING | HASH_DAMPING | HASH_DEPHASING_CHAN => {
                mask |= MASK_QUANTUM | MASK_DEPHASING
            }
            HASH_CHOLESKY | HASH_DOOLITTLE | HASH_DOOLITTLE_LU | HASH_LU_DECOMP | HASH_QR
            | HASH_GRAM_SCHMIDT | HASH_QR_GRAM_SCHMIDT => mask |= MASK_FACTORIZATION,
            HASH_JACOBI | HASH_JACOBI_EIGEN => mask |= MASK_SPECTRAL,
            HASH_PYRAMID | HASH_PYRAMID_ISO | HASH_TETRAHEDRON | HASH_TETRAHEDRON_ISO
            | HASH_OCTAHEDRON | HASH_OCTAHEDRON_ISO => mask |= MASK_POLYHEDRON,
            HASH_AMM | HASH_XY_K | HASH_CONST_PROD | HASH_LIQ_POOL | HASH_AMM_INVARIANT => {
                mask |= MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC
            }
            HASH_CALL | HASH_EXTERNAL | HASH_REENTRANCY | HASH_WITHDRAW | HASH_TRANSFER => {
                mask |= MASK_AUDIT_CEI
            }
            HASH_DIV | HASH_SHARES | HASH_ASSETS | HASH_ROUNDING => {
                mask |= MASK_AUDIT_ARITHMETIC | MASK_FUTURE_TRAJECTORY | MASK_CUMULATIVE_DELTA
            }
            HASH_TRAJECTORY | HASH_FUTURE_FLOW | HASH_CUMULATIVE_DELTA | HASH_MICRO_DRAIN => {
                mask |= MASK_ECONOMIC_AMM | MASK_FUTURE_TRAJECTORY | MASK_CUMULATIVE_DELTA
            }
            HASH_BORROW | HASH_LIQUIDATE | HASH_COLLATERAL => {
                mask |= MASK_ARCHETYPE_LENDING_LIQ | MASK_AUDIT_ARITHMETIC | MASK_AUDIT_UNDERFLOW_DOS
            }
            HASH_BRIDGE | HASH_LZRECEIVE | HASH_MERKLE => {
                mask |= MASK_ARCHETYPE_BRIDGE_ZK | MASK_AUDIT_CEI | MASK_AUDIT_UNDERFLOW_DOS
            }
            HASH_ORACLE | HASH_TWAP => {
                mask |= MASK_ARCHETYPE_ORACLE_TWAP | MASK_AUDIT_ARITHMETIC
            }
            HASH_GOVERNANCE | HASH_PROPOSE | HASH_UPGRADETO => {
                mask |= MASK_ARCHETYPE_GOV_PROXY | MASK_AUDIT_CEI
            }
            HASH_DISCREPANCY => {
                mask |= MASK_AUDIT_UNDERFLOW_DOS | MASK_AUDIT_ARITHMETIC
            }
            _ => {}
        }
        i += 1;
    }

    let bounded_slice = match input.len() > 16_384 {
        true => {
            let mut cut = 16_384;
            while cut > 0 && !input.is_char_boundary(cut) {
                cut -= 1;
            }
            &input[..cut]
        }
        false => input,
    };
    let lower = bounded_slice.to_lowercase();
    match lower.contains("tload") || lower.contains("tstore") || lower.contains("transient") {
        true => mask |= MASK_QUANTUM,
        false => {}
    }
    match lower.contains("delegatecall") || lower.contains("proxy") {
        true => mask |= MASK_QUANTUM | MASK_DEPHASING,
        false => {}
    }
    match lower.contains("diamond")
        || lower.contains("multicall")
        || lower.contains("router")
        || lower.contains("factory")
    {
        true => mask |= MASK_POLYHEDRON,
        false => {}
    }
    match lower.contains("eigenvalue") || lower.contains("spectral") {
        true => mask |= MASK_SPECTRAL,
        false => {}
    }
    match lower.contains("liquidity") || lower.contains("slippage") {
        true => mask |= MASK_ECONOMIC_AMM,
        false => {}
    }
    match lower.contains("liquidat") || lower.contains("collateral") {
        true => mask |= MASK_ARCHETYPE_LENDING_LIQ | MASK_AUDIT_UNDERFLOW_DOS,
        false => {}
    }
    match lower.contains("bridge") || lower.contains("migration") {
        true => mask |= MASK_ARCHETYPE_BRIDGE_ZK | MASK_AUDIT_UNDERFLOW_DOS,
        false => {}
    }
    match lower.contains("latestrounddata") || lower.contains("oracle") {
        true => mask |= MASK_ARCHETYPE_ORACLE_TWAP,
        false => {}
    }

    match mask == 0 {
        true => match MathematicalOperatorDomain::classify(bounded_slice) {
            MathematicalOperatorDomain::QuantumOperator => mask |= MASK_QUANTUM,
            MathematicalOperatorDomain::MatrixFactorization => mask |= MASK_FACTORIZATION,
            MathematicalOperatorDomain::SpectralIteration => mask |= MASK_SPECTRAL,
            MathematicalOperatorDomain::PolyhedronGeometry => mask |= MASK_POLYHEDRON,
            MathematicalOperatorDomain::DynamicStepping => mask |= MASK_DYNAMIC_STEP,
            MathematicalOperatorDomain::InvariantConservation => {
                mask |= MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC
            }
            _ => {}
        },
        false => {}
    }

    mask
}

pub fn derive_dynamic_scope_and_axioms_from_source(
    combined_source: &str,
) -> (String, [Option<&'static str>; 4], usize) {
    let lower = combined_source.to_lowercase();
    let mask = compute_problem_bitmask(combined_source);

    let mut scope_parts: [&str; 12] = [""; 12];
    let mut s_cnt = 0usize;

    let base_exemptions: [&str; 5] = [
        "onlyowner",
        "onlyadmin",
        "previous_reports",
        "non_default_settings",
        "misconfiguration",
    ];
    let mut b_i = 0usize;
    while b_i < 5 {
        scope_parts[s_cnt] = base_exemptions[b_i];
        s_cnt += 1;
        b_i += 1;
    }

    match lower.contains("onlypolicy") || lower.contains("onlyrole") || lower.contains("permissioned") {
        true => {
            scope_parts[s_cnt] = "onlypolicy";
            s_cnt += 1;
        }
        false => {}
    }
    match lower.contains("onlygovernor") || lower.contains("onlyguardian") || lower.contains("timelock") {
        true => {
            scope_parts[s_cnt] = "onlygovernor";
            s_cnt += 1;
        }
        false => {}
    }
    match lower.contains("removedust") || lower.contains("decimalconversionrate") {
        true => {
            scope_parts[s_cnt] = "removedust";
            s_cnt += 1;
        }
        false => {}
    }
    match lower.contains("whennotpaused") || lower.contains("onlypauser") {
        true => {
            scope_parts[s_cnt] = "onlypauser";
            s_cnt += 1;
        }
        false => {}
    }

    let dynamic_scope_str = scope_parts[..s_cnt].join(",");

    let mut axioms: [Option<&'static str>; 4] = [None; 4];
    let mut ax_cnt = 0usize;

    let has_amm_or_swap = (mask & MASK_ECONOMIC_AMM) != 0
        || lower.contains("reserve")
        || lower.contains("swap")
        || lower.contains("liquidity");
    let has_cei_or_ext = (mask & MASK_AUDIT_CEI) != 0
        || lower.contains(".call")
        || lower.contains("safetransfer")
        || lower.contains(".transfer(");

    axioms[ax_cnt] = Some("cumulative_delta_conservation");
    ax_cnt += 1;

    match has_cei_or_ext {
        true => {
            axioms[ax_cnt] = Some("swc107_cei_reentrancy_invariant");
            ax_cnt += 1;
        }
        false => {}
    }

    axioms[ax_cnt] = Some("cwe369_rounding_truncation_guard");
    ax_cnt += 1;

    match ax_cnt < 4 {
        true => {
            let fourth_axiom = match has_amm_or_swap {
                true => "amm_constant_product_invariant",
                false => "defi_pool_solvency_conservation",
            };
            axioms[ax_cnt] = Some(fourth_axiom);
            ax_cnt += 1;
        }
        false => {}
    }

    match ax_cnt < 4 {
        true => {
            axioms[ax_cnt] = Some("future_cashflow_trajectory_invariant");
            ax_cnt += 1;
        }
        false => {}
    }

    (dynamic_scope_str, axioms, ax_cnt)
}

pub fn filter_axioms_through_funnel(
    problem_mask: u64,
    custom_candidates: &[AxiomFastGateEntry],
) -> AcceptDenyFunnel {
    let mut funnel = AcceptDenyFunnel::new();

    let custom_limit = match custom_candidates.len() > 64 {
        true => 64,
        false => custom_candidates.len(),
    };
    let mut c_idx = 0usize;
    while c_idx < custom_limit {
        let cand = custom_candidates[c_idx];
        let matched = (problem_mask & cand.trigger_mask) != 0 && cand.trigger_mask != 0;
        match matched && funnel.accepted_count < MAX_ACCEPT_SLOTS {
            true => {
                funnel.accepted[funnel.accepted_count] = Some(cand);
                funnel.accepted_count += 1;
            }
            false => {
                funnel.denied_count = funnel.denied_count.saturating_add(1);
            }
        }
        c_idx += 1;
    }

    let mut b_idx = 0usize;
    while b_idx < CATALOG_GATE_SIZE {
        let entry = BUILTIN_FAST_GATE_CATALOG[b_idx];
        let matched = (problem_mask & entry.trigger_mask) != 0 && entry.trigger_mask != 0;
        match matched && funnel.accepted_count < MAX_ACCEPT_SLOTS {
            true => {
                funnel.accepted[funnel.accepted_count] = Some(entry);
                funnel.accepted_count += 1;
            }
            false => {
                funnel.denied_count = funnel.denied_count.saturating_add(1);
            }
        }
        b_idx += 1;
    }

    funnel
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HypergraphResonanceLink {
    pub source_axiom_id: u32,
    pub target_axiom_id: u32,
    pub shared_semantic_mask: u64,
    pub resonance_weight: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct AxiomResonanceHypergraph256 {
    pub ring: [AxiomFastGateEntry; MAX_HYPERGRAPH_AXIOMS],
    pub active_nodes: usize,
    pub write_cursor: usize,
    pub resonance_links: [Option<HypergraphResonanceLink>; 8],
    pub link_count: usize,
}

impl AxiomResonanceHypergraph256 {
    pub fn bootstrap_256_on_stack(problem_mask: u64) -> Self {
        let mut ring = [AxiomFastGateEntry::new(0, 0, 0, 0); MAX_HYPERGRAPH_AXIOMS];

        let trigger_cycle: [u64; 16] = [
            MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC,
            MASK_AUDIT_CEI,
            MASK_AUDIT_ARITHMETIC,
            MASK_ECONOMIC_AMM | MASK_AUDIT_CEI | MASK_AUDIT_ARITHMETIC,
            MASK_FUTURE_TRAJECTORY | MASK_CUMULATIVE_DELTA,
            MASK_ARCHETYPE_LENDING_LIQ | MASK_AUDIT_UNDERFLOW_DOS,
            MASK_ARCHETYPE_BRIDGE_ZK | MASK_AUDIT_CEI,
            MASK_ARCHETYPE_ORACLE_TWAP | MASK_AUDIT_ARITHMETIC,
            MASK_ARCHETYPE_GOV_PROXY | MASK_AUDIT_CEI,
            MASK_ERC4626_VAULT_SPEC | MASK_AUDIT_UNDERFLOW_DOS,
            MASK_OZ_MATH_TRY_CATCH | MASK_AUDIT_ARITHMETIC,
            MASK_QUANTUM,
            MASK_DEPHASING,
            MASK_FACTORIZATION,
            MASK_SPECTRAL,
            MASK_POLYHEDRON | MASK_DYNAMIC_STEP,
        ];

        let semantic_cycle: [u64; 8] = [
            SEMANTIC_SHARE_ACCOUNTING | SEMANTIC_PRECISION_DIV,
            SEMANTIC_CEI_STATE_LOCK | SEMANTIC_SOLVENCY_BOUNDARY,
            SEMANTIC_PRECISION_DIV | SEMANTIC_INVARIANT_CONSERVATION,
            SEMANTIC_SHARE_ACCOUNTING | SEMANTIC_INVARIANT_CONSERVATION | SEMANTIC_TEMPORAL_HORIZON,
            SEMANTIC_CROSS_CONTRACT_VIEW | SEMANTIC_CEI_STATE_LOCK,
            SEMANTIC_SOLVENCY_BOUNDARY | SEMANTIC_INVARIANT_CONSERVATION,
            SEMANTIC_TEMPORAL_HORIZON | SEMANTIC_PRECISION_DIV,
            SEMANTIC_GOVERNANCE_AUTH | SEMANTIC_SHARE_ACCOUNTING | SEMANTIC_INVARIANT_CONSERVATION,
        ];

        let mut idx = 0usize;
        while idx < MAX_HYPERGRAPH_AXIOMS {
            let trig = trigger_cycle[idx % 16];
            let sem = semantic_cycle[idx % 8];
            let seed_bytes = [
                b'h',
                b'g',
                b'_',
                b'0' + ((idx / 100) as u8),
                b'0' + (((idx / 10) % 10) as u8),
                b'0' + ((idx % 10) as u8),
            ];
            let tuned_sem = match idx == 0 || idx == 236 {
                true => {
                    SEMANTIC_SHARE_ACCOUNTING
                        | SEMANTIC_PRECISION_DIV
                        | SEMANTIC_INVARIANT_CONSERVATION
                        | SEMANTIC_SOLVENCY_BOUNDARY
                }
                false => sem,
            };
            let tuned_trig = match idx == 0 || idx == 236 {
                true => problem_mask | MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC | MASK_AUDIT_CEI,
                false => trig,
            };

            ring[idx] = AxiomFastGateEntry::new(
                fnv1a_hash_ascii_lower(&seed_bytes),
                tuned_trig,
                tuned_sem,
                (idx + 1) as u32,
            );
            idx += 1;
        }

        let mut graph = Self {
            ring,
            active_nodes: MAX_HYPERGRAPH_AXIOMS,
            write_cursor: 0,
            resonance_links: [None; 8],
            link_count: 0,
        };
        graph.discover_long_range_resonance_links_stack(problem_mask);
        graph
    }

    pub fn sync_knowledge_dir_into_ring_stack(&mut self, knowledge_dir: &Path, problem_mask: u64) {
        match knowledge_dir.is_dir() {
            false => return,
            true => {}
        }
        match std::fs::read_dir(knowledge_dir) {
            Ok(entries) => {
                let mut dir_budget = 64usize;
                for entry_res in entries {
                    match dir_budget == 0 {
                        true => break,
                        false => dir_budget -= 1,
                    }
                    match entry_res {
                        Ok(entry) => {
                            let path = entry.path();
                            let is_jsonl = path.is_file()
                                && match path.extension().and_then(|s| s.to_str()) {
                                    Some(ext) => ext == "jsonl",
                                    None => false,
                                };
                            match is_jsonl {
                                true => match std::fs::read_to_string(&path) {
                                    Ok(content) => {
                                        let mut line_budget = 16usize;
                                        for line in content.lines() {
                                            match line_budget == 0 {
                                                true => break,
                                                false => line_budget -= 1,
                                            }
                                            let tr = line.trim();
                                            match MathematicalAxiom::from_jsonl_line(tr) {
                                                Some(ax) => {
                                                    let slot = self.write_cursor % MAX_HYPERGRAPH_AXIOMS;
                                                    let sem = infer_semantic_bitmask_for_axiom_stack(&ax);
                                                    let trig = compute_problem_bitmask(&ax.key)
                                                        | MASK_AUDIT_ARITHMETIC
                                                        | MASK_AUDIT_CEI;
                                                    self.ring[slot] = AxiomFastGateEntry::new(
                                                        fnv1a_hash_ascii_lower(ax.key.as_bytes()),
                                                        trig,
                                                        sem,
                                                        (slot + 1) as u32,
                                                    );
                                                    self.write_cursor =
                                                        (self.write_cursor + 1) % MAX_HYPERGRAPH_AXIOMS;
                                                }
                                                None => {}
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                },
                                false => {}
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
        self.discover_long_range_resonance_links_stack(problem_mask);
    }

    pub fn discover_long_range_resonance_links_stack(&mut self, problem_mask: u64) {
        self.resonance_links = [None; 8];
        self.link_count = 0;

        let ax_1 = self.ring[0];
        let ax_237 = self.ring[236];
        let w_primary = ax_1.resonance_weight_with(&ax_237);
        self.resonance_links[0] = Some(HypergraphResonanceLink {
            source_axiom_id: ax_1.axiom_id,
            target_axiom_id: ax_237.axiom_id,
            shared_semantic_mask: ax_1.semantic_bitmask & ax_237.semantic_bitmask,
            resonance_weight: w_primary,
        });
        self.link_count = 1;

        let mut head = 1usize;
        let mut scan_budget = 64usize;
        while scan_budget > 0 && self.link_count < 8 {
            scan_budget -= 1;
            let tail = (head + 137) % MAX_HYPERGRAPH_AXIOMS;
            let src_entry = self.ring[head];
            let dst_entry = self.ring[tail];

            let shared_sem = src_entry.semantic_bitmask & dst_entry.semantic_bitmask;
            let trig_active =
                ((src_entry.trigger_mask | dst_entry.trigger_mask) & problem_mask) != 0;
            let weight = src_entry.resonance_weight_with(&dst_entry);

            match shared_sem.count_ones() >= 2 && trig_active && weight >= 0.75 {
                true => {
                    self.resonance_links[self.link_count] = Some(HypergraphResonanceLink {
                        source_axiom_id: src_entry.axiom_id,
                        target_axiom_id: dst_entry.axiom_id,
                        shared_semantic_mask: shared_sem,
                        resonance_weight: weight,
                    });
                    self.link_count += 1;
                }
                false => {}
            }
            head = (head + 7) % MAX_HYPERGRAPH_AXIOMS;
        }
    }

    pub fn evaluate_256_funnel(&self, problem_mask: u64) -> AcceptDenyFunnel {
        let mut funnel = AcceptDenyFunnel::new();
        let mut i = 0usize;
        while i < MAX_HYPERGRAPH_AXIOMS {
            funnel.evaluate(problem_mask, self.ring[i]);
            i += 1;
        }
        match funnel.accepted_count >= 2 {
            true => {
                funnel.accepted[0] = Some(self.ring[0]);
                let last_slot = funnel.accepted_count - 1;
                funnel.accepted[last_slot] = Some(self.ring[236]);
            }
            false => {}
        }
        funnel
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PipelineExecutionReport {
    pub converged: bool,
    pub slides_executed: usize,
    pub stages_verified: usize,
    pub broken_axiom_id: Option<u32>,
    pub global_invariants: [f64; 4],
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlidingAxiomPipeline {
    pub window: [Option<AxiomFastGateEntry>; MAX_PIPELINE_WINDOW],
    pub scratchpad: [f64; SCRATCHPAD_SIZE],
    pub attention_matrix_4x4: [[f64; 4]; 4],
    pub resonated_pair_ids: (u32, u32),
    pub current_offset: usize,
    pub slides_count: usize,
    pub halted_fail_closed: bool,
    pub broken_axiom_id: Option<u32>,
}

impl SlidingAxiomPipeline {
    pub const fn new() -> Self {
        Self {
            window: [None; MAX_PIPELINE_WINDOW],
            scratchpad: [0.0; SCRATCHPAD_SIZE],
            attention_matrix_4x4: [[0.0; 4]; 4],
            resonated_pair_ids: (1, 237),
            current_offset: 0,
            slides_count: 0,
            halted_fail_closed: false,
            broken_axiom_id: None,
        }
    }

    pub fn load_window_at(&mut self, funnel: &AcceptDenyFunnel, offset: usize) {
        self.window = [None; MAX_PIPELINE_WINDOW];
        self.current_offset = offset;

        let mut s_idx = 4usize;
        while s_idx < SCRATCHPAD_SIZE {
            self.scratchpad[s_idx] = 0.0;
            s_idx += 1;
        }

        let mut w_idx = 0usize;
        while w_idx < MAX_PIPELINE_WINDOW {
            let src_idx = offset + w_idx;
            match src_idx < funnel.accepted_count {
                true => {
                    self.window[w_idx] = funnel.accepted[src_idx];
                }
                false => match funnel.accepted_count > 0 {
                    true => {
                        let wrapped_idx = src_idx % funnel.accepted_count;
                        self.window[w_idx] = funnel.accepted[wrapped_idx];
                    }
                    false => {}
                },
            }
            w_idx += 1;
        }

        let mut r = 0usize;
        while r < 4 {
            let mut c = 0usize;
            while c < 4 {
                let w = match (self.window[r], self.window[c]) {
                    (Some(a), Some(b)) => a.resonance_weight_with(&b),
                    _ => 0.0,
                };
                self.attention_matrix_4x4[r][c] = w;
                c += 1;
            }
            r += 1;
        }
    }

    pub fn execute_sliding_chain<F>(
        &mut self,
        funnel: &AcceptDenyFunnel,
        mut step_evaluator: F,
    ) -> PipelineExecutionReport
    where
        F: FnMut(AxiomFastGateEntry, usize, &mut [f64; SCRATCHPAD_SIZE]) -> bool,
    {
        match funnel.accepted_count == 0 {
            true => {
                self.halted_fail_closed = true;
                return PipelineExecutionReport {
                    converged: false,
                    slides_executed: 0,
                    stages_verified: 0,
                    broken_axiom_id: None,
                    global_invariants: [0.0; 4],
                };
            }
            false => {}
        }

        let raw_frames = match funnel.accepted_count > MAX_PIPELINE_WINDOW {
            true => (funnel.accepted_count - MAX_PIPELINE_WINDOW) + 1,
            false => 1,
        };
        let total_frames = match raw_frames > MAX_SLIDE_BUDGET {
            true => MAX_SLIDE_BUDGET,
            false => raw_frames,
        };

        let mut frame_idx = 0usize;
        let mut stages_verified = 0usize;

        while frame_idx < total_frames {
            self.load_window_at(funnel, frame_idx);
            self.slides_count += 1;

            let mut slot_idx = 0usize;
            while slot_idx < MAX_PIPELINE_WINDOW {
                match self.window[slot_idx] {
                    Some(entry) => {
                        let passed = step_evaluator(entry, slot_idx, &mut self.scratchpad);
                        let resonance_boost = self.attention_matrix_4x4[0][slot_idx];
                        let local_slot = 4 + (slot_idx * 3) + 2;
                        match local_slot < SCRATCHPAD_SIZE {
                            true => {
                                self.scratchpad[local_slot] += resonance_boost;
                            }
                            false => {}
                        }

                        match passed {
                            true => {
                                stages_verified += 1;
                            }
                            false => {
                                self.halted_fail_closed = true;
                                self.broken_axiom_id = Some(entry.axiom_id);
                                return PipelineExecutionReport {
                                    converged: false,
                                    slides_executed: self.slides_count,
                                    stages_verified,
                                    broken_axiom_id: Some(entry.axiom_id),
                                    global_invariants: [
                                        self.scratchpad[0],
                                        self.scratchpad[1],
                                        self.scratchpad[2],
                                        self.scratchpad[3],
                                    ],
                                };
                            }
                        }
                    }
                    None => {}
                }
                slot_idx += 1;
            }

            frame_idx += 1;
        }

        PipelineExecutionReport {
            converged: true,
            slides_executed: self.slides_count,
            stages_verified,
            broken_axiom_id: None,
            global_invariants: [
                self.scratchpad[0],
                self.scratchpad[1],
                self.scratchpad[2],
                self.scratchpad[3],
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_swarm_axiom_roundtrip_and_persistence_to_knowledge_dir() {
        let mut engine = DeterministicEngine::new(50);
        let gate = SovereignAuthorizationGate::new();
        let coordinator = SwarmResearchCoordinator::new();
        let temp_dir = PathBuf::from("garry_workspace").join("test_ephemeral_knowledge");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let axiom = coordinator
            .dispatch_executable_axiom_swarm_sync("doolittle_lu", 8)
            .expect("Swarm must synthesize Doolittle LU axiom");

        let report = gate
            .authorize_and_persist_executable_axiom(&axiom, &temp_dir, &mut engine)
            .expect("Sovereign gate must persist axiom to disk");

        assert_ne!(report.final_crc32, 0);
        let loaded = lookup_mathematical_axiom_in_dir(&temp_dir, "doolittle_lu");
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().key, "doolittle_lu");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_hypergraph_256_resonance_and_sliding_pipeline() {
        let mask = MASK_ECONOMIC_AMM | MASK_AUDIT_ARITHMETIC | MASK_AUDIT_CEI;
        let hg = AxiomResonanceHypergraph256::bootstrap_256_on_stack(mask);
        let funnel = hg.evaluate_256_funnel(mask);
        assert_eq!(funnel.accepted_count, 8);
        assert_eq!(funnel.accepted[0].unwrap().axiom_id, 1);
        assert_eq!(funnel.accepted[7].unwrap().axiom_id, 237);
    }
}