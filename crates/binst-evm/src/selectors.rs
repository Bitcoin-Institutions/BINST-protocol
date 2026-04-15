//! ABI selector constants for BINST contracts.
//!
//! All selectors are verified against compiled Hardhat artifacts.

// ── BINSTProcessFactory ──────────────────────────────────────────

/// `createInstance(string,string[],string[])` → `0x6f794b70`
pub const CREATE_INSTANCE: [u8; 4] = [0x6f, 0x79, 0x4b, 0x70];

/// `getInstanceCount()` → `0xae34325c`
pub const GET_INSTANCE_COUNT: [u8; 4] = [0xae, 0x34, 0x32, 0x5c];

/// `allInstances(uint256)` → `0x9b0dc489`
pub const ALL_INSTANCES: [u8; 4] = [0x9b, 0x0d, 0xc4, 0x89];

/// `getUserInstances(address)` → `0xfceaae17`
pub const GET_USER_INSTANCES: [u8; 4] = [0xfc, 0xea, 0xae, 0x17];

/// `getTemplateInstances(string)` → `0xb43bed00`
pub const GET_TEMPLATE_INSTANCES: [u8; 4] = [0xb4, 0x3b, 0xed, 0x00];

// ── BINSTProcess ─────────────────────────────────────────────────

/// `executeStep(uint8,string)` → `0xf16e3a23`
pub const EXECUTE_STEP: [u8; 4] = [0xf1, 0x6e, 0x3a, 0x23];

/// `currentStepIndex()` → `0x334f45ec`
pub const CURRENT_STEP_INDEX: [u8; 4] = [0x33, 0x4f, 0x45, 0xec];

/// `completed()` → `0x9d9a7fe9`
pub const COMPLETED: [u8; 4] = [0x9d, 0x9a, 0x7f, 0xe9];

/// `totalSteps()` → `0x6931b3ae`
pub const TOTAL_STEPS: [u8; 4] = [0x69, 0x31, 0xb3, 0xae];

/// `creator()` → `0x02d05d3f`
pub const CREATOR: [u8; 4] = [0x02, 0xd0, 0x5d, 0x3f];

/// `templateInscriptionId()` → `0x0270a0b3`
pub const TEMPLATE_INSCRIPTION_ID: [u8; 4] = [0x02, 0x70, 0xa0, 0xb3];

/// `getStepCount()` → `0x6fd63351`
pub const GET_STEP_COUNT: [u8; 4] = [0x6f, 0xd6, 0x33, 0x51];

/// `getStep(uint256)` → `0x7874888a`
pub const GET_STEP: [u8; 4] = [0x78, 0x74, 0x88, 0x8a];

/// `getStepState(uint256)` → `0xac5b070a`
pub const GET_STEP_STATE: [u8; 4] = [0xac, 0x5b, 0x07, 0x0a];

/// `isCompleted()` → `0xfa391c64`
pub const IS_COMPLETED: [u8; 4] = [0xfa, 0x39, 0x1c, 0x64];

// ── Event topics ─────────────────────────────────────────────────

/// `InstanceCreated(address,address,string,uint256)` — keccak256 topic0
pub const INSTANCE_CREATED_TOPIC: &str =
    "a3de24f67beb38e771bb8aca2ec9e03485fedd4f4c7379d840ecc7cdd7f0700f";

/// `StepExecuted(uint256,address,uint8,string)` — keccak256 topic0
pub const STEP_EXECUTED_TOPIC: &str =
    "5b89aea554e20d06eec989a91e330f07430146585616a53676b168e42a331b82";
