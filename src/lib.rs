//! Garry Core: Deterministic Finite State Machine (FSM), Stack-Bounded Storage (16 Slots),
//! Interval SMT Prover, EVM Bytecode Ground-Truth Anchor, and Adversarial Refutation Engine.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - STACK-BOUNDED CORE - ZERO EXTERNAL CRATES - FAIL-CLOSED]

pub mod audit;
pub mod bytecode_anchor;
pub mod crc;
pub mod ephemeral;
pub mod interactive;
pub mod metering;
pub mod patch_verify;
pub mod plan;
pub mod prng;
pub mod refutation;
pub mod sensory_planner;
pub mod solver;
pub mod suspicion_filter;

pub mod evm {
    pub use crate::bytecode_anchor::*;
}

pub mod execution {
    pub use crate::patch_verify::*;
}

pub use bytecode_anchor::{
    decode_hex_bytecode_stack, strip_cbor_metadata_length, BytecodeAnchorProfile,
    BytecodeGroundTruthAnchor, MAX_ANCHORED_SELECTORS, MAX_BYTECODE_BYTES,
};
pub use crc::{
    calculate_crc32, compute_crc32, crc32, make_crc_table, CRC32_POLYNOMIAL, CRC_TABLE,
};
pub use metering::{LogicalClock, MeterConfig, StepMeter};
pub use patch_verify::{
    AutoPatchRecommendation, PatchVerificationMatrixEngine, PatchVerificationMatrixReport,
    PatchVerificationStatus, MAX_AUTO_PATCH_BYTES, MAX_SECONDARY_POC_BYTES,
};
pub use prng::{Xorshift64Star, PRNG_FALLBACK_SEED, XORSHIFT_STAR_MULTIPLIER};
pub use refutation::{
    AdversarialChallengeBundle, ClaimedVulnerabilityKind, LogicAdversaryEngine, RefutationRound,
    RefutationVerdict, SelfCorrectionInput, SelfCorrectionVerdict,
};
pub use suspicion_filter::{
    DeterministicSmtProver, MultiLayerSuspicionFilter, SmtConstraint, SmtDomainInterval,
    SmtRelationOp, SmtSatResult, SuspicionCandidate, SuspicionVerdict, MAX_SMT_CONSTRAINTS,
    MAX_SMT_PROPAGATION_STEPS, MAX_SMT_VARS, MAX_SUSPICION_SCAN_BYTES,
};

use core::fmt;
use core::marker::PhantomData;

pub const AUDIT_LOG_CAPACITY: usize = 64;
pub const MAX_KEY_SIZE: usize = 32;
pub const MAX_VALUE_SIZE: usize = 256;
pub const MAX_STORAGE_SLOTS: usize = 16;
pub const MAX_REGISTERED_ACTIONS: usize = 16;

pub const CHECKPOINT_MAGIC: &[u8; 8] = b"GARRYSNP";
pub const CHECKPOINT_VERSION: u16 = 3;
pub const MAX_EVENT_TAG_SIZE: usize = 32;
pub const CHECKPOINT_SIZE: usize = 7865;
pub const DEFAULT_PRNG_SEED: u64 = 0x517C_C1B7_2722_0A95;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EngineError {
    BudgetExceeded { limit: u32, current: u32 },
    QuotaExceeded { limit: u64, current: u64 },
    MaxEpochsExceeded { limit: u32, current: u32 },
    InvalidTransition { from: EngineState, to: EngineState },
    IllegalTransition { from: EngineState, event: &'static str },
    TerminalState(EngineState),
    TerminalStateReached { state: EngineState },
    ValidationFailed { reason: &'static str },
    GuardViolation { reason: &'static str },
    ExecutionFailed { reason: &'static str },
    StorageFull { limit: usize },
    PayloadTooLarge,
    HandlerNotFound(&'static str),
    RegistryFull { limit: usize },
    BufferTooSmall { required: usize, provided: usize },
    InvalidCheckpointMagic,
    UnsupportedCheckpointVersion(u16),
    CheckpointChecksumMismatch { expected: u32, found: u32 },
    InvalidStateDiscriminant(u8),
    CorruptedCheckpoint { reason: &'static str },
    PlanGraphFull { limit: usize },
    InvalidDependency { node_id: usize, dep_id: usize },
    NodeNotFound(usize),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::BudgetExceeded { limit, current } => write!(
                f,
                "Execution budget exceeded: limit was {}, reached {}",
                limit, current
            ),
            EngineError::QuotaExceeded { limit, current } => write!(
                f,
                "Compute quota exceeded: limit is {} units, required {} units",
                limit, current
            ),
            EngineError::MaxEpochsExceeded { limit, current } => write!(
                f,
                "Maximum epoch limit exceeded: limit was {}, reached {}",
                limit, current
            ),
            EngineError::InvalidTransition { from, to } => write!(
                f,
                "Invalid state transition from {:?} to {:?}",
                from, to
            ),
            EngineError::IllegalTransition { from, event } => write!(
                f,
                "Illegal transition attempted from {:?} via event {}",
                from, event
            ),
            EngineError::TerminalState(state) => write!(
                f,
                "Terminal state {:?} reached; execution halts",
                state
            ),
            EngineError::TerminalStateReached { state } => write!(
                f,
                "Operation rejected: engine is already in terminal state {:?}",
                state
            ),
            EngineError::ValidationFailed { reason } => write!(
                f,
                "Action validation failed: {}",
                reason
            ),
            EngineError::GuardViolation { reason } => write!(
                f,
                "Guard condition failed: {}",
                reason
            ),
            EngineError::ExecutionFailed { reason } => write!(
                f,
                "Action execution failed: {}",
                reason
            ),
            EngineError::StorageFull { limit } => write!(
                f,
                "Memory storage is full: slot limit of {} reached",
                limit
            ),
            EngineError::PayloadTooLarge => write!(
                f,
                "Payload exceeds maximum permitted size"
            ),
            EngineError::HandlerNotFound(action_type) => write!(
                f,
                "Action handler not registered for type: {}",
                action_type
            ),
            EngineError::RegistryFull { limit } => write!(
                f,
                "Action registry capacity reached: {}",
                limit
            ),
            EngineError::BufferTooSmall { required, provided } => write!(
                f,
                "Buffer too small for checkpoint: required {}, provided {}",
                required, provided
            ),
            EngineError::InvalidCheckpointMagic => write!(
                f,
                "Invalid checkpoint magic identifier"
            ),
            EngineError::UnsupportedCheckpointVersion(ver) => write!(
                f,
                "Unsupported checkpoint version: {}",
                ver
            ),
            EngineError::CheckpointChecksumMismatch { expected, found } => write!(
                f,
                "Corrupted checkpoint checksum mismatch: expected {:#010X}, found {:#010X}",
                expected, found
            ),
            EngineError::InvalidStateDiscriminant(disc) => write!(
                f,
                "Invalid state discriminant in checkpoint: {}",
                disc
            ),
            EngineError::CorruptedCheckpoint { reason } => write!(
                f,
                "Corrupted checkpoint data: {}",
                reason
            ),
            EngineError::PlanGraphFull { limit } => write!(
                f,
                "Plan graph capacity reached: limit is {}",
                limit
            ),
            EngineError::InvalidDependency { node_id, dep_id } => write!(
                f,
                "Invalid dependency index: node {} references invalid dependency {}",
                node_id, dep_id
            ),
            EngineError::NodeNotFound(id) => write!(
                f,
                "Node not found in plan graph: id {}",
                id
            ),
        }
    }
}

impl std::error::Error for EngineError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineState {
    Idle,
    Planning,
    Executing,
    Verifying,
    Completed,
    Failed,
}

pub type AgentState = EngineState;

impl EngineState {
    pub const fn to_u8(self) -> u8 {
        match self {
            EngineState::Idle => 0,
            EngineState::Planning => 1,
            EngineState::Executing => 2,
            EngineState::Verifying => 3,
            EngineState::Completed => 4,
            EngineState::Failed => 5,
        }
    }

    pub fn from_u8(val: u8) -> Result<Self, EngineError> {
        match val {
            0 => Ok(EngineState::Idle),
            1 => Ok(EngineState::Planning),
            2 => Ok(EngineState::Executing),
            3 => Ok(EngineState::Verifying),
            4 => Ok(EngineState::Completed),
            5 => Ok(EngineState::Failed),
            other => Err(EngineError::InvalidStateDiscriminant(other)),
        }
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(self, EngineState::Completed | EngineState::Failed)
    }
}

fn resolve_event_tag(bytes: &[u8]) -> Result<&'static str, EngineError> {
    const KNOWN_TAGS: &[&str] = &[
        "TriggerPlanning",
        "DispatchAction",
        "ActionExecutionComplete",
        "RollbackOnFailure",
        "VerificationPassed",
        "VerificationFailedRetry",
        "AbortSignal",
        "StateTransition",
        "EpochBudgetExhausted",
    ];

    for &tag in KNOWN_TAGS {
        match tag.as_bytes() == bytes {
            true => return Ok(tag),
            false => {}
        }
    }

    Err(EngineError::CorruptedCheckpoint {
        reason: "Unrecognized event tag in audit record",
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionRecord {
    pub tick: u64,
    pub step: u32,
    pub from: EngineState,
    pub to: EngineState,
    pub event_tag: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingBufferAuditLog<const CAP: usize> {
    pub records: [Option<TransitionRecord>; CAP],
    pub head: usize,
    pub total_records: usize,
}

impl<const CAP: usize> RingBufferAuditLog<CAP> {
    pub const fn new() -> Self {
        Self {
            records: [None; CAP],
            head: 0,
            total_records: 0,
        }
    }

    pub fn push(&mut self, record: TransitionRecord) {
        self.records[self.head] = Some(record);
        self.head = (self.head + 1) % CAP;
        self.total_records = self.total_records.saturating_add(1);
    }

    pub fn len(&self) -> usize {
        match self.total_records < CAP {
            true => self.total_records,
            false => CAP,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total_records == 0
    }

    pub fn get_latest(&self) -> Option<&TransitionRecord> {
        match self.total_records {
            0 => None,
            _ => {
                let last_index = match self.head {
                    0 => CAP - 1,
                    h => h - 1,
                };
                self.records[last_index].as_ref()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedStorage {
    pub slots: [Option<([u8; MAX_KEY_SIZE], usize, [u8; MAX_VALUE_SIZE], usize)>; MAX_STORAGE_SLOTS],
    pub count: usize,
}

impl BoundedStorage {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_STORAGE_SLOTS],
            count: 0,
        }
    }

    #[inline(always)]
    pub fn snapshot(&self) -> Self {
        *self
    }

    #[inline(always)]
    pub fn restore(&mut self, snapshot: Self) {
        *self = snapshot;
    }

    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), EngineError> {
        match key.len() > MAX_KEY_SIZE || value.len() > MAX_VALUE_SIZE {
            true => return Err(EngineError::PayloadTooLarge),
            false => {}
        }

        for slot in self.slots.iter_mut() {
            match slot {
                Some((k_buf, k_len, v_buf, v_len)) => match &k_buf[..*k_len] == key {
                    true => {
                        v_buf[..value.len()].copy_from_slice(value);
                        *v_len = value.len();
                        return Ok(());
                    }
                    false => {}
                },
                None => {}
            }
        }

        match self.count >= MAX_STORAGE_SLOTS {
            true => {
                return Err(EngineError::StorageFull {
                    limit: MAX_STORAGE_SLOTS,
                })
            }
            false => {}
        }

        for slot in self.slots.iter_mut() {
            match slot {
                None => {
                    let mut k_buf = [0u8; MAX_KEY_SIZE];
                    let mut v_buf = [0u8; MAX_VALUE_SIZE];
                    k_buf[..key.len()].copy_from_slice(key);
                    v_buf[..value.len()].copy_from_slice(value);
                    *slot = Some((k_buf, key.len(), v_buf, value.len()));
                    self.count += 1;
                    return Ok(());
                }
                Some(_) => {}
            }
        }

        Err(EngineError::StorageFull {
            limit: MAX_STORAGE_SLOTS,
        })
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        for slot in self.slots.iter().flatten() {
            match &slot.0[..slot.1] == key {
                true => return Some(&slot.2[..slot.3]),
                false => {}
            }
        }
        None
    }

    pub fn remove(&mut self, key: &[u8]) -> bool {
        for slot in self.slots.iter_mut() {
            match slot {
                Some((k_buf, k_len, _, _)) => match &k_buf[..*k_len] == key {
                    true => {
                        *slot = None;
                        self.count = self.count.saturating_sub(1);
                        return true;
                    }
                    false => {}
                },
                None => {}
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

pub type SimpleActionHandlerFn = fn(&[u8], &mut BoundedStorage) -> Result<(), EngineError>;
pub type FullActionHandlerFn =
    fn(&[u8], &mut BoundedStorage, &mut Xorshift64Star, &mut StepMeter) -> Result<(), EngineError>;

pub trait IntoActionHandler<Marker> {
    fn into_action_handler(self) -> ActionHandler;
}

pub struct SimpleHandlerMarker;
pub struct FullHandlerMarker;

#[derive(Clone, Copy)]
pub struct ActionHandler {
    trampoline:
        fn(*const (), &[u8], &mut BoundedStorage, &mut Xorshift64Star, &mut StepMeter) -> Result<(), EngineError>,
    ptr: *const (),
}

unsafe impl Send for ActionHandler {}
unsafe impl Sync for ActionHandler {}

impl ActionHandler {
    pub fn dispatch(
        &self,
        payload: &[u8],
        storage: &mut BoundedStorage,
        prng: &mut Xorshift64Star,
        meter: &mut StepMeter,
    ) -> Result<(), EngineError> {
        (self.trampoline)(self.ptr, payload, storage, prng, meter)
    }
}

impl<F> IntoActionHandler<SimpleHandlerMarker> for F
where
    F: Fn(&[u8], &mut BoundedStorage) -> Result<(), EngineError> + Copy + Send + Sync + 'static,
{
    fn into_action_handler(self) -> ActionHandler {
        fn trampoline<T: Fn(&[u8], &mut BoundedStorage) -> Result<(), EngineError> + Copy>(
            ptr: *const (),
            payload: &[u8],
            storage: &mut BoundedStorage,
            _prng: &mut Xorshift64Star,
            _meter: &mut StepMeter,
        ) -> Result<(), EngineError> {
            match core::mem::size_of::<T>() {
                0 => {
                    let f = unsafe { core::mem::zeroed::<T>() };
                    f(payload, storage)
                }
                _ => {
                    let f = unsafe { core::mem::transmute_copy::<*const (), T>(&ptr) };
                    f(payload, storage)
                }
            }
        }
        let ptr = match core::mem::size_of::<F>() {
            0 => core::ptr::null(),
            _ => unsafe { core::mem::transmute_copy::<F, *const ()>(&self) },
        };
        ActionHandler {
            trampoline: trampoline::<F>,
            ptr,
        }
    }
}

impl<F> IntoActionHandler<FullHandlerMarker> for F
where
    F: Fn(&[u8], &mut BoundedStorage, &mut Xorshift64Star, &mut StepMeter) -> Result<(), EngineError>
        + Copy
        + Send
        + Sync
        + 'static,
{
    fn into_action_handler(self) -> ActionHandler {
        fn trampoline<
            T: Fn(&[u8], &mut BoundedStorage, &mut Xorshift64Star, &mut StepMeter) -> Result<(), EngineError>
                + Copy,
        >(
            ptr: *const (),
            payload: &[u8],
            storage: &mut BoundedStorage,
            prng: &mut Xorshift64Star,
            meter: &mut StepMeter,
        ) -> Result<(), EngineError> {
            match core::mem::size_of::<T>() {
                0 => {
                    let f = unsafe { core::mem::zeroed::<T>() };
                    f(payload, storage, prng, meter)
                }
                _ => {
                    let f = unsafe { core::mem::transmute_copy::<*const (), T>(&ptr) };
                    f(payload, storage, prng, meter)
                }
            }
        }
        let ptr = match core::mem::size_of::<F>() {
            0 => core::ptr::null(),
            _ => unsafe { core::mem::transmute_copy::<F, *const ()>(&self) },
        };
        ActionHandler {
            trampoline: trampoline::<F>,
            ptr,
        }
    }
}

impl IntoActionHandler<SimpleHandlerMarker> for ActionHandler {
    fn into_action_handler(self) -> ActionHandler {
        self
    }
}

#[derive(Clone, Copy)]
pub struct ActionRegistry {
    handlers: [Option<(&'static str, ActionHandler)>; MAX_REGISTERED_ACTIONS],
    count: usize,
}

impl ActionRegistry {
    pub const fn new() -> Self {
        Self {
            handlers: [None; MAX_REGISTERED_ACTIONS],
            count: 0,
        }
    }

    pub fn register(
        &mut self,
        action_type: &'static str,
        handler: ActionHandler,
    ) -> Result<(), EngineError> {
        for entry in self.handlers.iter_mut() {
            match entry {
                Some((existing_type, existing_handler)) => match *existing_type == action_type {
                    true => {
                        *existing_handler = handler;
                        return Ok(());
                    }
                    false => {}
                },
                None => {}
            }
        }

        match self.count >= MAX_REGISTERED_ACTIONS {
            true => {
                return Err(EngineError::RegistryFull {
                    limit: MAX_REGISTERED_ACTIONS,
                })
            }
            false => {}
        }

        for entry in self.handlers.iter_mut() {
            match entry {
                None => {
                    *entry = Some((action_type, handler));
                    self.count += 1;
                    return Ok(());
                }
                Some(_) => {}
            }
        }

        Err(EngineError::RegistryFull {
            limit: MAX_REGISTERED_ACTIONS,
        })
    }

    pub fn dispatch(
        &self,
        action_type: &'static str,
        payload: &[u8],
        storage: &mut BoundedStorage,
        prng: &mut Xorshift64Star,
        meter: &mut StepMeter,
    ) -> Result<(), EngineError> {
        for entry in self.handlers.iter().flatten() {
            match entry.0 == action_type {
                true => return entry.1.dispatch(payload, storage, prng, meter),
                false => {}
            }
        }
        Err(EngineError::HandlerNotFound(action_type))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unchecked;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validated;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionProposal<Stage> {
    action_type: &'static str,
    payload: [u8; MAX_VALUE_SIZE],
    payload_len: usize,
    marker: PhantomData<Stage>,
}

impl ActionProposal<Unchecked> {
    pub fn new(action_type: &'static str, raw_payload: &[u8]) -> Result<Self, EngineError> {
        match raw_payload.len() > MAX_VALUE_SIZE {
            true => Err(EngineError::PayloadTooLarge),
            false => {
                let mut payload = [0u8; MAX_VALUE_SIZE];
                payload[..raw_payload.len()].copy_from_slice(raw_payload);

                Ok(Self {
                    action_type,
                    payload,
                    payload_len: raw_payload.len(),
                    marker: PhantomData,
                })
            }
        }
    }

    pub fn validate(
        self,
        min_payload_size: usize,
    ) -> Result<ActionProposal<Validated>, EngineError> {
        match self.payload_len < min_payload_size {
            true => Err(EngineError::ValidationFailed {
                reason: "Payload is smaller than required minimum length",
            }),
            false => Ok(ActionProposal {
                action_type: self.action_type,
                payload: self.payload,
                payload_len: self.payload_len,
                marker: PhantomData,
            }),
        }
    }
}

impl ActionProposal<Validated> {
    pub fn action_type(&self) -> &'static str {
        self.action_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

struct ByteWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> ByteWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn written_bytes(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), EngineError> {
        let end = self.offset + data.len();
        match end > self.buf.len() {
            true => Err(EngineError::BufferTooSmall {
                required: end,
                provided: self.buf.len(),
            }),
            false => {
                self.buf[self.offset..end].copy_from_slice(data);
                self.offset = end;
                Ok(())
            }
        }
    }

    fn write_u8(&mut self, val: u8) -> Result<(), EngineError> {
        self.write_bytes(&[val])
    }

    fn write_u16(&mut self, val: u16) -> Result<(), EngineError> {
        self.write_bytes(&val.to_le_bytes())
    }

    fn write_u32(&mut self, val: u32) -> Result<(), EngineError> {
        self.write_bytes(&val.to_le_bytes())
    }

    fn write_u64(&mut self, val: u64) -> Result<(), EngineError> {
        self.write_bytes(&val.to_le_bytes())
    }
}

struct ByteReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], EngineError> {
        let end = self.offset + len;
        match end > self.buf.len() {
            true => Err(EngineError::CorruptedCheckpoint {
                reason: "Unexpected end of buffer while reading fields",
            }),
            false => {
                let slice = &self.buf[self.offset..end];
                self.offset = end;
                Ok(slice)
            }
        }
    }

    fn read_u8(&mut self) -> Result<u8, EngineError> {
        let slice = self.read_bytes(1)?;
        Ok(slice[0])
    }

    fn read_u16(&mut self) -> Result<u16, EngineError> {
        let slice = self.read_bytes(2)?;
        let mut arr = [0u8; 2];
        arr.copy_from_slice(slice);
        Ok(u16::from_le_bytes(arr))
    }

    fn read_u32(&mut self) -> Result<u32, EngineError> {
        let slice = self.read_bytes(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(slice);
        Ok(u32::from_le_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, EngineError> {
        let slice = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(slice);
        Ok(u64::from_le_bytes(arr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointMetadata {
    pub version: u16,
    pub state: EngineState,
    pub epoch: u32,
    pub tick: u64,
    pub prng_state: u64,
    pub consumed_steps: u32,
    pub max_steps: u32,
    pub consumed_units: u64,
    pub max_units: u64,
    pub total_records: usize,
    pub storage_slots_used: usize,
    pub checksum: u32,
}

impl CheckpointMetadata {
    pub fn inspect(data: &[u8]) -> Result<Self, EngineError> {
        match data.len() < CHECKPOINT_SIZE {
            true => {
                return Err(EngineError::BufferTooSmall {
                    required: CHECKPOINT_SIZE,
                    provided: data.len(),
                })
            }
            false => {}
        }

        let payload_len = CHECKPOINT_SIZE - 4;
        let expected_checksum = u32::from_le_bytes([
            data[payload_len],
            data[payload_len + 1],
            data[payload_len + 2],
            data[payload_len + 3],
        ]);
        let calculated_checksum = calculate_crc32(&data[..payload_len]);

        match expected_checksum != calculated_checksum {
            true => {
                return Err(EngineError::CheckpointChecksumMismatch {
                    expected: expected_checksum,
                    found: calculated_checksum,
                })
            }
            false => {}
        }

        match &data[0..8] == CHECKPOINT_MAGIC {
            true => {}
            false => return Err(EngineError::InvalidCheckpointMagic),
        }

        let version = u16::from_le_bytes([data[8], data[9]]);
        match version == CHECKPOINT_VERSION {
            true => {}
            false => return Err(EngineError::UnsupportedCheckpointVersion(version)),
        }

        let state = EngineState::from_u8(data[10])?;
        let epoch = u32::from_le_bytes([data[11], data[12], data[13], data[14]]);
        let tick = u64::from_le_bytes([
            data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22],
        ]);
        let prng_state = u64::from_le_bytes([
            data[23], data[24], data[25], data[26], data[27], data[28], data[29], data[30],
        ]);
        let max_steps = u32::from_le_bytes([data[31], data[32], data[33], data[34]]);
        let max_units = u64::from_le_bytes([
            data[35], data[36], data[37], data[38], data[39], data[40], data[41], data[42],
        ]);
        let consumed_steps = u32::from_le_bytes([data[83], data[84], data[85], data[86]]);
        let consumed_units = u64::from_le_bytes([
            data[87], data[88], data[89], data[90], data[91], data[92], data[93], data[94],
        ]);

        let total_records = u64::from_le_bytes([
            data[95], data[96], data[97], data[98], data[99], data[100], data[101], data[102],
        ]) as usize;

        let storage_slots_used = u16::from_le_bytes([data[3185], data[3186]]) as usize;

        Ok(Self {
            version,
            state,
            epoch,
            tick,
            prng_state,
            consumed_steps,
            max_steps,
            consumed_units,
            max_units,
            total_records,
            storage_slots_used,
            checksum: expected_checksum,
        })
    }
}

pub struct DeterministicEngine {
    state: EngineState,
    clock: LogicalClock,
    meter: StepMeter,
    prng: Xorshift64Star,
    audit_log: RingBufferAuditLog<AUDIT_LOG_CAPACITY>,
    storage: BoundedStorage,
    registry: ActionRegistry,
}

impl DeterministicEngine {
    pub fn new(max_steps: u32) -> Self {
        Self::with_seed_and_meter_config(DEFAULT_PRNG_SEED, MeterConfig::standard(max_steps))
    }

    pub fn with_seed(max_steps: u32, seed: u64) -> Self {
        Self::with_seed_and_meter_config(seed, MeterConfig::standard(max_steps))
    }

    pub fn with_seed_and_meter_config(seed: u64, config: MeterConfig) -> Self {
        Self {
            state: EngineState::Idle,
            clock: LogicalClock::new(),
            meter: StepMeter::new(config),
            prng: Xorshift64Star::new(seed),
            audit_log: RingBufferAuditLog::new(),
            storage: BoundedStorage::new(),
            registry: ActionRegistry::new(),
        }
    }

    pub fn register_action<H, M>(
        &mut self,
        action_type: &'static str,
        handler: H,
    ) -> Result<(), EngineError>
    where
        H: IntoActionHandler<M>,
    {
        self.registry
            .register(action_type, handler.into_action_handler())
    }

    pub fn state(&self) -> EngineState {
        self.state
    }

    pub fn current_state(&self) -> &EngineState {
        &self.state
    }

    pub fn clock(&self) -> &LogicalClock {
        &self.clock
    }

    pub fn clock_mut(&mut self) -> &mut LogicalClock {
        &mut self.clock
    }

    pub fn meter(&self) -> &StepMeter {
        &self.meter
    }

    pub fn meter_mut(&mut self) -> &mut StepMeter {
        &mut self.meter
    }

    pub fn prng(&self) -> &Xorshift64Star {
        &self.prng
    }

    pub fn prng_mut(&mut self) -> &mut Xorshift64Star {
        &mut self.prng
    }

    pub fn next_random_u64(&mut self) -> Result<u64, EngineError> {
        self.prng.next_u64(&mut self.meter)
    }

    pub fn current_step(&self) -> u32 {
        self.meter.consumed_steps()
    }

    pub fn step_budget(&self) -> u32 {
        self.meter.config().max_steps
    }

    pub fn audit_log(&self) -> &RingBufferAuditLog<AUDIT_LOG_CAPACITY> {
        &self.audit_log
    }

    pub fn storage(&self) -> &BoundedStorage {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut BoundedStorage {
        &mut self.storage
    }

    pub fn transition_to(&mut self, next_state: EngineState) -> Result<(), EngineError> {
        match self.state.is_terminal() {
            true => return Err(EngineError::TerminalStateReached { state: self.state }),
            false => {}
        }

        let is_valid = match (&self.state, &next_state) {
            (EngineState::Idle, EngineState::Planning) => true,
            (EngineState::Planning, EngineState::Executing) => true,
            (EngineState::Planning, EngineState::Verifying) => true,
            (EngineState::Planning, EngineState::Failed) => true,
            (EngineState::Executing, EngineState::Verifying) => true,
            (EngineState::Executing, EngineState::Failed) => true,
            (EngineState::Verifying, EngineState::Planning) => true,
            (EngineState::Verifying, EngineState::Completed) => true,
            (EngineState::Verifying, EngineState::Failed) => true,
            _ => false,
        };

        match is_valid {
            true => {
                let tick = self.clock.advance_tick();
                let record = TransitionRecord {
                    tick,
                    step: self.meter.consumed_steps(),
                    from: self.state,
                    to: next_state,
                    event_tag: "StateTransition",
                };

                self.audit_log.push(record);
                self.state = next_state;
                Ok(())
            }
            false => Err(EngineError::InvalidTransition {
                from: self.state,
                to: next_state,
            }),
        }
    }

    pub fn apply_transition(
        &mut self,
        next_state: EngineState,
        event_tag: &'static str,
    ) -> Result<(), EngineError> {
        match self.state.is_terminal() {
            true => Err(EngineError::TerminalState(self.state)),
            false => {
                self.meter.charge_step()?;
                self.meter.charge_transition()?;
                let tick = self.clock.advance_tick();

                let record = TransitionRecord {
                    tick,
                    step: self.meter.consumed_steps(),
                    from: self.state,
                    to: next_state,
                    event_tag,
                };

                self.audit_log.push(record);
                self.state = next_state;
                Ok(())
            }
        }
    }

    pub fn trigger_planning(&mut self) -> Result<(), EngineError> {
        match self.state {
            EngineState::Idle | EngineState::Verifying => {
                self.clock.advance_epoch();
                self.apply_transition(EngineState::Planning, "TriggerPlanning")
            }
            EngineState::Planning => Ok(()),
            invalid => Err(EngineError::IllegalTransition {
                from: invalid,
                event: "TriggerPlanning",
            }),
        }
    }

    pub fn execute_proposal(
        &mut self,
        proposal: ActionProposal<Validated>,
    ) -> Result<(), EngineError> {
        match self.state {
            EngineState::Planning => {
                let storage_checkpoint = self.storage.snapshot();
                let prng_checkpoint = self.prng;

                self.apply_transition(EngineState::Executing, "DispatchAction")?;

                let execution_result = (|| -> Result<(), EngineError> {
                    self.meter.charge_storage_write(
                        b"last_executed_type".len() + proposal.action_type().len(),
                    )?;
                    self.storage
                        .set(b"last_executed_type", proposal.action_type().as_bytes())?;
                    self.registry.dispatch(
                        proposal.action_type(),
                        proposal.payload(),
                        &mut self.storage,
                        &mut self.prng,
                        &mut self.meter,
                    )?;
                    self.apply_transition(EngineState::Verifying, "ActionExecutionComplete")?;
                    Ok(())
                })();

                match execution_result {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        self.storage.restore(storage_checkpoint);
                        self.prng = prng_checkpoint;

                        let tick = self.clock.advance_tick();
                        let rollback_record = TransitionRecord {
                            tick,
                            step: self.meter.consumed_steps(),
                            from: EngineState::Executing,
                            to: EngineState::Planning,
                            event_tag: "RollbackOnFailure",
                        };
                        self.audit_log.push(rollback_record);
                        self.state = EngineState::Planning;
                        Err(err)
                    }
                }
            }
            invalid => Err(EngineError::IllegalTransition {
                from: invalid,
                event: "DispatchAction",
            }),
        }
    }

    pub fn finalize_verification(&mut self, goal_reached: bool) -> Result<(), EngineError> {
        match (self.state, goal_reached) {
            (EngineState::Verifying, true) => {
                self.apply_transition(EngineState::Completed, "VerificationPassed")
            }
            (EngineState::Verifying, false) => {
                self.clock.advance_epoch();
                self.apply_transition(EngineState::Planning, "VerificationFailedRetry")
            }
            (invalid, _) => Err(EngineError::IllegalTransition {
                from: invalid,
                event: "FinalizeVerification",
            }),
        }
    }

    pub fn fail_epoch_limit(&mut self, limit: u32, current: u32) -> Result<(), EngineError> {
        self.apply_transition(EngineState::Failed, "EpochBudgetExhausted")?;
        Err(EngineError::MaxEpochsExceeded { limit, current })
    }

    pub fn abort(&mut self) -> Result<(), EngineError> {
        self.apply_transition(EngineState::Failed, "AbortSignal")
    }

    pub fn export_checkpoint(&self, out: &mut [u8]) -> Result<usize, EngineError> {
        match out.len() < CHECKPOINT_SIZE {
            true => {
                return Err(EngineError::BufferTooSmall {
                    required: CHECKPOINT_SIZE,
                    provided: out.len(),
                })
            }
            false => {}
        }

        let mut writer = ByteWriter::new(out);

        writer.write_bytes(CHECKPOINT_MAGIC)?;
        writer.write_u16(CHECKPOINT_VERSION)?;

        writer.write_u8(self.state.to_u8())?;
        writer.write_u32(self.clock.epoch())?;
        writer.write_u64(self.clock.tick())?;
        writer.write_u64(self.prng.state())?;

        let cfg = self.meter.config();
        writer.write_u32(cfg.max_steps)?;
        writer.write_u64(cfg.max_units)?;
        writer.write_u64(cfg.step_cost)?;
        writer.write_u64(cfg.transition_cost)?;
        writer.write_u64(cfg.storage_read_byte_cost)?;
        writer.write_u64(cfg.storage_write_byte_cost)?;
        writer.write_u64(cfg.prng_cost)?;

        writer.write_u32(self.meter.consumed_steps())?;
        writer.write_u64(self.meter.consumed_units())?;

        writer.write_u64(self.audit_log.total_records as u64)?;
        writer.write_u64(self.audit_log.head as u64)?;
        writer.write_u16(AUDIT_LOG_CAPACITY as u16)?;

        for record_opt in self.audit_log.records.iter() {
            match record_opt {
                Some(record) => {
                    writer.write_u8(1)?;
                    writer.write_u64(record.tick)?;
                    writer.write_u32(record.step)?;
                    writer.write_u8(record.from.to_u8())?;
                    writer.write_u8(record.to.to_u8())?;

                    let tag_bytes = record.event_tag.as_bytes();
                    let tag_len = tag_bytes.len().min(MAX_EVENT_TAG_SIZE);
                    writer.write_u8(tag_len as u8)?;

                    let mut tag_buf = [0u8; MAX_EVENT_TAG_SIZE];
                    tag_buf[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);
                    writer.write_bytes(&tag_buf)?;
                }
                None => {
                    writer.write_u8(0)?;
                    writer.write_u64(0)?;
                    writer.write_u32(0)?;
                    writer.write_u8(0)?;
                    writer.write_u8(0)?;
                    writer.write_u8(0)?;
                    writer.write_bytes(&[0u8; MAX_EVENT_TAG_SIZE])?;
                }
            }
        }

        writer.write_u16(self.storage.count as u16)?;
        writer.write_u16(MAX_STORAGE_SLOTS as u16)?;

        for slot_opt in self.storage.slots.iter() {
            match slot_opt {
                Some((k_buf, k_len, v_buf, v_len)) => {
                    writer.write_u8(1)?;
                    writer.write_u8(*k_len as u8)?;
                    writer.write_bytes(k_buf)?;
                    writer.write_u16(*v_len as u16)?;
                    writer.write_bytes(v_buf)?;
                }
                None => {
                    writer.write_u8(0)?;
                    writer.write_u8(0)?;
                    writer.write_bytes(&[0u8; MAX_KEY_SIZE])?;
                    writer.write_u16(0)?;
                    writer.write_bytes(&[0u8; MAX_VALUE_SIZE])?;
                }
            }
        }

        let checksum = calculate_crc32(writer.written_bytes());
        writer.write_u32(checksum)?;

        Ok(CHECKPOINT_SIZE)
    }

    pub fn export_checkpoint_array(&self) -> [u8; CHECKPOINT_SIZE] {
        let mut buf = [0u8; CHECKPOINT_SIZE];
        self.export_checkpoint(&mut buf)
            .expect("Static buffer guaranteed to match CHECKPOINT_SIZE");
        buf
    }

    pub fn import_checkpoint(&mut self, data: &[u8]) -> Result<(), EngineError> {
        match data.len() < CHECKPOINT_SIZE {
            true => {
                return Err(EngineError::BufferTooSmall {
                    required: CHECKPOINT_SIZE,
                    provided: data.len(),
                })
            }
            false => {}
        }

        let payload_len = CHECKPOINT_SIZE - 4;
        let expected_checksum = u32::from_le_bytes([
            data[payload_len],
            data[payload_len + 1],
            data[payload_len + 2],
            data[payload_len + 3],
        ]);
        let calculated_checksum = calculate_crc32(&data[..payload_len]);

        match expected_checksum != calculated_checksum {
            true => {
                return Err(EngineError::CheckpointChecksumMismatch {
                    expected: expected_checksum,
                    found: calculated_checksum,
                })
            }
            false => {}
        }

        let mut reader = ByteReader::new(&data[..payload_len]);

        let magic = reader.read_bytes(8)?;
        match magic == CHECKPOINT_MAGIC {
            true => {}
            false => return Err(EngineError::InvalidCheckpointMagic),
        }

        let version = reader.read_u16()?;
        match version == CHECKPOINT_VERSION {
            true => {}
            false => return Err(EngineError::UnsupportedCheckpointVersion(version)),
        }

        let state = EngineState::from_u8(reader.read_u8()?)?;
        let epoch = reader.read_u32()?;
        let tick = reader.read_u64()?;
        let prng_state = reader.read_u64()?;

        let max_steps = reader.read_u32()?;
        let max_units = reader.read_u64()?;
        let step_cost = reader.read_u64()?;
        let transition_cost = reader.read_u64()?;
        let storage_read_byte_cost = reader.read_u64()?;
        let storage_write_byte_cost = reader.read_u64()?;
        let prng_cost = reader.read_u64()?;

        let consumed_steps = reader.read_u32()?;
        let consumed_units = reader.read_u64()?;

        let total_records = reader.read_u64()? as usize;
        let head = reader.read_u64()? as usize;
        let audit_cap = reader.read_u16()? as usize;

        match audit_cap == AUDIT_LOG_CAPACITY {
            true => {}
            false => {
                return Err(EngineError::CorruptedCheckpoint {
                    reason: "Audit log capacity mismatch",
                })
            }
        }

        match head >= AUDIT_LOG_CAPACITY {
            true => {
                return Err(EngineError::CorruptedCheckpoint {
                    reason: "Audit log head out of bounds",
                })
            }
            false => {}
        }

        let mut restored_records = [None; AUDIT_LOG_CAPACITY];
        for slot in restored_records.iter_mut() {
            let is_active = reader.read_u8()?;
            let tick_val = reader.read_u64()?;
            let step_val = reader.read_u32()?;
            let from_raw = reader.read_u8()?;
            let to_raw = reader.read_u8()?;
            let tag_len = reader.read_u8()? as usize;
            let tag_bytes = reader.read_bytes(MAX_EVENT_TAG_SIZE)?;

            match is_active {
                0 => {}
                _ => {
                    match tag_len > MAX_EVENT_TAG_SIZE {
                        true => {
                            return Err(EngineError::CorruptedCheckpoint {
                                reason: "Event tag length exceeds limit",
                            })
                        }
                        false => {}
                    }
                    let from = EngineState::from_u8(from_raw)?;
                    let to = EngineState::from_u8(to_raw)?;
                    let tag_str = resolve_event_tag(&tag_bytes[..tag_len])?;

                    *slot = Some(TransitionRecord {
                        tick: tick_val,
                        step: step_val,
                        from,
                        to,
                        event_tag: tag_str,
                    });
                }
            }
        }

        let storage_count = reader.read_u16()? as usize;
        let storage_slots_limit = reader.read_u16()? as usize;

        match storage_slots_limit == MAX_STORAGE_SLOTS {
            true => {}
            false => {
                return Err(EngineError::CorruptedCheckpoint {
                    reason: "Storage slot capacity mismatch",
                })
            }
        }

        match storage_count > MAX_STORAGE_SLOTS {
            true => {
                return Err(EngineError::CorruptedCheckpoint {
                    reason: "Storage entry count exceeds maximum slots",
                })
            }
            false => {}
        }

        let mut restored_slots = [None; MAX_STORAGE_SLOTS];
        let mut actual_occupied = 0;
        for slot in restored_slots.iter_mut() {
            let is_occupied = reader.read_u8()?;
            let key_len = reader.read_u8()? as usize;
            let key_raw = reader.read_bytes(MAX_KEY_SIZE)?;
            let val_len = reader.read_u16()? as usize;
            let val_raw = reader.read_bytes(MAX_VALUE_SIZE)?;

            match is_occupied {
                0 => {}
                _ => {
                    match key_len > MAX_KEY_SIZE || val_len > MAX_VALUE_SIZE {
                        true => {
                            return Err(EngineError::CorruptedCheckpoint {
                                reason: "Storage key or value length exceeds limit",
                            })
                        }
                        false => {}
                    }

                    let mut k_buf = [0u8; MAX_KEY_SIZE];
                    let mut v_buf = [0u8; MAX_VALUE_SIZE];
                    k_buf[..MAX_KEY_SIZE].copy_from_slice(key_raw);
                    v_buf[..MAX_VALUE_SIZE].copy_from_slice(val_raw);

                    *slot = Some((k_buf, key_len, v_buf, val_len));
                    actual_occupied += 1;
                }
            }
        }

        match actual_occupied == storage_count {
            true => {}
            false => {
                return Err(EngineError::CorruptedCheckpoint {
                    reason: "Storage slot count mismatch with header count",
                })
            }
        }

        self.state = state;
        self.clock = LogicalClock::from_raw(epoch, tick);
        self.prng = Xorshift64Star::from_raw(prng_state);

        let restored_config = MeterConfig {
            max_steps,
            max_units,
            step_cost,
            transition_cost,
            storage_read_byte_cost,
            storage_write_byte_cost,
            prng_cost,
        };
        self.meter = StepMeter::from_raw(restored_config, consumed_steps, consumed_units);
        self.audit_log = RingBufferAuditLog {
            records: restored_records,
            head,
            total_records,
        };
        self.storage = BoundedStorage {
            slots: restored_slots,
            count: storage_count,
        };

        Ok(())
    }
}