//! Shared input/output types for the three update steps.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Step1In {
    pub finalized_header_json: String,
    pub current_committee_ssz: Vec<u8>,
    pub next_committee_ssz: Option<Vec<u8>>,
    pub update_json: String,
    pub is_finality_update: bool,
    pub expected_current_slot: u64,
    pub genesis_root: [u8; 32],
    pub forks_json: String,
    /// The keys step 1 aggregates, supplied uncompressed by whoever submits the
    /// update, so step 1 decompresses none: the signing committee's aggregate
    /// key, then each non-signer's key in committee order, 96 bytes each (blst
    /// affine serialization). Step 1 checks that each is on the curve and
    /// compresses to the committee's key. `None`: step 1 decompresses them.
    pub supplied_keys: Option<Vec<u8>>,
}

/// What step 1 leaves for step 2 (in a LEZ program: a job account).
#[derive(Serialize, Deserialize)]
pub struct Job {
    pub pk: Vec<u8>,  // signers' aggregate key, blst affine serialization (96 bytes)
    pub sig: Vec<u8>, // signature point (192 bytes)
    pub hm: Vec<u8>,  // H(signing root) on G2 (192 bytes)
}

/// What step 2 leaves for step 3: the Miller-loop output (Fp12, 576 bytes).
#[derive(Serialize, Deserialize)]
pub struct Miller {
    pub f: Vec<u8>,
}
