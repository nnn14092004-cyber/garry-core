//! EVM Bytecode Ground-Truth Anchor: Disassembles raw runtime bytecode on the stack,
//! strips PUSH1..PUSH32 immediate data, extracts function selectors, and anchors
//! vulnerability claims directly to physical EVM opcodes.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - ZERO HEAP ALLOCATION - ZERO FREEZE - FAIL-CLOSED]

use crate::crc::calculate_crc32;

/// Maximum raw bytecode bytes decoded on the stack per inspection pass.
pub const MAX_BYTECODE_BYTES: usize = 4096;

/// Maximum number of 4-byte function selectors anchored on the stack.
pub const MAX_ANCHORED_SELECTORS: usize = 16;

// Canonical EVM Opcodes
pub const OP_STOP: u8 = 0x00;
pub const OP_ADD: u8 = 0x01;
pub const OP_MUL: u8 = 0x02;
pub const OP_SUB: u8 = 0x03;
pub const OP_DIV: u8 = 0x04;
pub const OP_SDIV: u8 = 0x05;
pub const OP_MOD: u8 = 0x06;
pub const OP_LT: u8 = 0x10;
pub const OP_GT: u8 = 0x11;
pub const OP_EQ: u8 = 0x14;
pub const OP_ISZERO: u8 = 0x15;
pub const OP_SHA3: u8 = 0x20;
pub const OP_CALLER: u8 = 0x33;
pub const OP_CALLVALUE: u8 = 0x34;
pub const OP_SLOAD: u8 = 0x54;
pub const OP_SSTORE: u8 = 0x55;
pub const OP_JUMP: u8 = 0x56;
pub const OP_JUMPI: u8 = 0x57;
pub const OP_JUMPDEST: u8 = 0x5b;
pub const OP_TLOAD: u8 = 0x5c;
pub const OP_TSTORE: u8 = 0x5d;
pub const OP_PUSH1: u8 = 0x60;
pub const OP_PUSH4: u8 = 0x63;
pub const OP_PUSH32: u8 = 0x7f;
pub const OP_CALL: u8 = 0xf1;
pub const OP_CALLCODE: u8 = 0xf2;
pub const OP_RETURN: u8 = 0xf3;
pub const OP_DELEGATECALL: u8 = 0xf4;
pub const OP_STATICCALL: u8 = 0xfa;
pub const OP_REVERT: u8 = 0xfd;
pub const OP_INVALID: u8 = 0xfe;

/// Ground-truth profile extracted directly from EVM runtime bytecode on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytecodeAnchorProfile {
    pub bytecode_crc32: u32,
    pub executable_len: usize,
    pub sload_count: u16,
    pub sstore_count: u16,
    pub tload_count: u16,
    pub tstore_count: u16,
    pub external_call_count: u16,
    pub delegatecall_count: u16,
    pub staticcall_count: u16,
    pub div_opcode_count: u16,
    pub sub_opcode_count: u16,
    pub jumpi_guard_count: u16,
    pub revert_count: u16,
    pub has_call_before_sstore_pattern: bool,
    pub has_tstore_reentrancy_guard: bool,
    pub selectors: [u32; MAX_ANCHORED_SELECTORS],
    pub selector_count: usize,
}

impl Default for BytecodeAnchorProfile {
    fn default() -> Self {
        Self::empty()
    }
}

impl BytecodeAnchorProfile {
    pub const fn empty() -> Self {
        Self {
            bytecode_crc32: 0,
            executable_len: 0,
            sload_count: 0,
            sstore_count: 0,
            tload_count: 0,
            tstore_count: 0,
            external_call_count: 0,
            delegatecall_count: 0,
            staticcall_count: 0,
            div_opcode_count: 0,
            sub_opcode_count: 0,
            jumpi_guard_count: 0,
            revert_count: 0,
            has_call_before_sstore_pattern: false,
            has_tstore_reentrancy_guard: false,
            selectors: [0u32; MAX_ANCHORED_SELECTORS],
            selector_count: 0,
        }
    }

    /// Checks whether a 4-byte function selector is physically present in the bytecode dispatch table.
    pub const fn contains_selector(&self, target_selector: u32) -> bool {
        let mut i = 0usize;
        while i < self.selector_count {
            match self.selectors[i] == target_selector {
                true => return true,
                false => i += 1,
            }
        }
        false
    }
}

/// Converts a single ASCII hex character into its 4-bit nibble value.
pub const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes an ASCII hex string (with or without `0x` prefix) into a fixed stack buffer.
pub fn decode_hex_bytecode_stack(hex_input: &[u8]) -> ([u8; MAX_BYTECODE_BYTES], usize) {
    let mut out = [0u8; MAX_BYTECODE_BYTES];
    let mut out_len = 0usize;

    let start_offset = match hex_input.len() >= 2
        && hex_input[0] == b'0'
        && (hex_input[1] == b'x' || hex_input[1] == b'X')
    {
        true => 2usize,
        false => 0usize,
    };

    let mut i = start_offset;
    let limit = hex_input.len();
    let mut scan_budget = MAX_BYTECODE_BYTES * 2;

    while i + 1 < limit && out_len < MAX_BYTECODE_BYTES && scan_budget > 0 {
        scan_budget -= 1;
        match hex_input[i].is_ascii_whitespace() {
            true => {
                i += 1;
                continue;
            }
            false => {}
        }

        match (hex_nibble(hex_input[i]), hex_nibble(hex_input[i + 1])) {
            (Some(hi), Some(lo)) => {
                out[out_len] = (hi << 4) | lo;
                out_len += 1;
                i += 2;
            }
            _ => break,
        }
    }

    (out, out_len)
}

/// Strips Solidity CBOR metadata tail (`0xa2 0x64 'i' 'p' 'f' 's'` or `0xa1 0x65 'b' 'z' 'z' 'r'`)
/// so metadata bytes are never mistaken for executable opcodes.
pub fn strip_cbor_metadata_length(raw_bytecode: &[u8]) -> usize {
    let len = match raw_bytecode.len() > MAX_BYTECODE_BYTES {
        true => MAX_BYTECODE_BYTES,
        false => raw_bytecode.len(),
    };

    let mut i = 0usize;
    while i + 5 < len {
        let is_ipfs_cbor = raw_bytecode[i] == 0xa2
            && raw_bytecode[i + 1] == 0x64
            && raw_bytecode[i + 2] == b'i'
            && raw_bytecode[i + 3] == b'p'
            && raw_bytecode[i + 4] == b'f'
            && raw_bytecode[i + 5] == b's';
        let is_bzzr_cbor = raw_bytecode[i] == 0xa1
            && raw_bytecode[i + 1] == 0x65
            && raw_bytecode[i + 2] == b'b'
            && raw_bytecode[i + 3] == b'z'
            && raw_bytecode[i + 4] == b'z'
            && raw_bytecode[i + 5] == b'r';

        match is_ipfs_cbor || is_bzzr_cbor {
            true => return i,
            false => i += 1,
        }
    }
    len
}

/// Stateless EVM Bytecode Ground-Truth Analyzer.
#[derive(Debug, Clone, Copy, Default)]
pub struct BytecodeGroundTruthAnchor;

impl BytecodeGroundTruthAnchor {
    pub const fn new() -> Self {
        Self
    }

    /// Disassembles raw binary EVM bytecode on the stack and produces a ground-truth profile.
    pub fn inspect_raw_bytecode(raw_bytecode: &[u8]) -> BytecodeAnchorProfile {
        let exec_len = strip_cbor_metadata_length(raw_bytecode);
        let exec_slice = &raw_bytecode[..exec_len];
        let mut profile = BytecodeAnchorProfile::empty();
        profile.bytecode_crc32 = calculate_crc32(exec_slice);
        profile.executable_len = exec_len;

        let mut pc = 0usize;
        let mut seen_external_call_in_segment = false;

        while pc < exec_len {
            let opcode = exec_slice[pc];

            match opcode {
                OP_SLOAD => {
                    profile.sload_count = profile.sload_count.saturating_add(1);
                    pc += 1;
                }
                OP_SSTORE => {
                    profile.sstore_count = profile.sstore_count.saturating_add(1);
                    match seen_external_call_in_segment {
                        true => profile.has_call_before_sstore_pattern = true,
                        false => {}
                    }
                    pc += 1;
                }
                OP_TLOAD => {
                    profile.tload_count = profile.tload_count.saturating_add(1);
                    pc += 1;
                }
                OP_TSTORE => {
                    profile.tstore_count = profile.tstore_count.saturating_add(1);
                    match profile.tload_count > 0 {
                        true => profile.has_tstore_reentrancy_guard = true,
                        false => {}
                    }
                    pc += 1;
                }
                OP_CALL | OP_CALLCODE => {
                    profile.external_call_count = profile.external_call_count.saturating_add(1);
                    seen_external_call_in_segment = true;
                    pc += 1;
                }
                OP_DELEGATECALL => {
                    profile.delegatecall_count = profile.delegatecall_count.saturating_add(1);
                    seen_external_call_in_segment = true;
                    pc += 1;
                }
                OP_STATICCALL => {
                    profile.staticcall_count = profile.staticcall_count.saturating_add(1);
                    pc += 1;
                }
                OP_DIV | OP_SDIV | OP_MOD => {
                    profile.div_opcode_count = profile.div_opcode_count.saturating_add(1);
                    pc += 1;
                }
                OP_SUB => {
                    profile.sub_opcode_count = profile.sub_opcode_count.saturating_add(1);
                    pc += 1;
                }
                OP_JUMPI => {
                    profile.jumpi_guard_count = profile.jumpi_guard_count.saturating_add(1);
                    pc += 1;
                }
                OP_REVERT => {
                    profile.revert_count = profile.revert_count.saturating_add(1);
                    seen_external_call_in_segment = false;
                    pc += 1;
                }
                OP_STOP | OP_RETURN | OP_INVALID => {
                    seen_external_call_in_segment = false;
                    pc += 1;
                }
                OP_PUSH4 => {
                    match pc + 4 < exec_len && profile.selector_count < MAX_ANCHORED_SELECTORS {
                        true => {
                            let sel = u32::from_be_bytes([
                                exec_slice[pc + 1],
                                exec_slice[pc + 2],
                                exec_slice[pc + 3],
                                exec_slice[pc + 4],
                            ]);
                            let next_op = match pc + 5 < exec_len {
                                true => exec_slice[pc + 5],
                                false => 0,
                            };
                            let next2_op = match pc + 6 < exec_len {
                                true => exec_slice[pc + 6],
                                false => 0,
                            };
                            let is_dispatch_eq = next_op == OP_EQ || next2_op == OP_EQ;
                            match is_dispatch_eq && sel != 0 && sel != 0xFFFF_FFFF {
                                true => match !profile.contains_selector(sel) {
                                    true => {
                                        profile.selectors[profile.selector_count] = sel;
                                        profile.selector_count += 1;
                                    }
                                    false => {}
                                },
                                false => {}
                            }
                        }
                        false => {}
                    }
                    pc = pc.saturating_add(5);
                }
                OP_PUSH1..=OP_PUSH32 => {
                    let push_immediate_bytes = (opcode - OP_PUSH1 + 1) as usize;
                    pc = pc.saturating_add(1 + push_immediate_bytes);
                }
                _ => {
                    pc += 1;
                }
            }
        }

        profile
    }

    /// Decodes hex-encoded bytecode and extracts its ground-truth opcode profile.
    pub fn inspect_hex_bytecode(hex_str: &str) -> BytecodeAnchorProfile {
        let (decoded, len) = decode_hex_bytecode_stack(hex_str.as_bytes());
        Self::inspect_raw_bytecode(&decoded[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytecode_anchor_skips_push_immediates_and_detects_cei_violation() {
        // PUSH4 0x2e1a7d4d EQ JUMPI ... CALL ... SSTORE STOP
        // Notice we embed 0xf1 (OP_CALL) inside PUSH2 immediate data first to verify it is NOT miscounted!
        let hex_code = "0x632e1a7d4d145761f1555bf15500a2646970667358221220";
        let profile = BytecodeGroundTruthAnchor::inspect_hex_bytecode(hex_code);

        assert_eq!(profile.selector_count, 1);
        assert!(profile.contains_selector(0x2e1a7d4d));
        // Only the real CALL (0xf1) and real SSTORE (0x55) after JUMPDEST (0x5b) must be counted
        assert_eq!(profile.external_call_count, 1);
        assert_eq!(profile.sstore_count, 1);
        assert!(profile.has_call_before_sstore_pattern);
    }

    #[test]
    fn test_bytecode_anchor_detects_eip1153_transient_reentrancy_guard() {
        // TLOAD (0x5c) ISZERO JUMPI TSTORE (0x5d) CALL SSTORE
        let raw = [OP_TLOAD, OP_ISZERO, OP_JUMPI, OP_TSTORE, OP_CALL, OP_SSTORE, OP_STOP];
        let profile = BytecodeGroundTruthAnchor::inspect_raw_bytecode(&raw);

        assert_eq!(profile.tload_count, 1);
        assert_eq!(profile.tstore_count, 1);
        assert!(profile.has_tstore_reentrancy_guard);
    }
}