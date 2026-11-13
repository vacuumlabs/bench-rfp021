//! Unpatched Helios, patched Helios and the three steps, compared on the same
//! updates.
//!
//! Two sides run the same cases, each on its own Helios types:
//! - `upstream`: a16z/helios at the pinned commit, unpatched;
//! - `patched`: this workspace's Helios, with our two hooks. It also runs every
//!   update through the three steps natively (`helios_check_steps`), once
//!   decompressing the signers' keys and once with them supplied.
//!
//! Each side records every update's verdicts and the store afterwards. The
//! tests (`tests/equivalence.rs`) require every verdict to equal unpatched
//! Helios's, and the stores to stay the same.
//!
//! The cases: Helios's own consensus-specs sync tests (its `testdata`), the
//! whole consensus-specs release if fetched, and the mainnet fixtures with
//! tampered and re-signed copies.

use std::path::Path;

use alloy_primitives::{b256, B256};
use helios_check_steps::Refusal;
use helios_consensus_core::{
    calc_sync_period,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    errors::ConsensusError,
    types::{bls::PublicKey, FinalityUpdate, Fork, Forks, GenericUpdate, LightClientStore, Update},
};
use serde::Deserialize;
use serde_json::{json, Value};
use ssz::Encode;
use tree_hash::TreeHash;

/// Accepted, or the error message.
pub type Verdict = Result<(), String>;

/// What the tests compare of a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub finalized: (u64, [u8; 32]),
    pub optimistic: (u64, [u8; 32]),
    pub next_committee: Option<[u8; 32]>,
}

/// One update (or forced update) a side ran.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub case: String,
    /// Helios's verdict, then the three steps' if the side runs them. Empty
    /// for a forced update.
    pub verdicts: Vec<(&'static str, Verdict)>,
    /// The store afterwards (a valid update in a sync test is applied).
    pub store: Snapshot,
}

// ---------------------------------------------------------------------------
// The three steps (patched side only)

/// The update through the three steps natively, once decompressing the
/// signers' keys and once with them supplied. A refusal reads as Helios's
/// error: a failed rule as that rule's, anything about the signature as
/// "invalid sync committee signature".
pub fn split<S: ConsensusSpec>(
    update: &GenericUpdate<S>,
    slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
) -> Vec<(&'static str, Verdict)> {
    let keys = supplied_keys(update, store);
    vec![
        ("three steps, keys decompressed", three_steps(update, slot, store, genesis_root, forks, None)),
        ("three steps, keys supplied", three_steps(update, slot, store, genesis_root, forks, keys.as_deref())),
    ]
}

/// What unpatched Helios runs besides itself: nothing.
pub fn no_split<U, St, F>(_: &U, _: u64, _: &St, _: B256, _: &F) -> Vec<(&'static str, Verdict)> {
    Vec::new()
}

fn three_steps<S: ConsensusSpec>(
    update: &GenericUpdate<S>,
    slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
    keys: Option<&[u8]>,
) -> Verdict {
    let invalid_signature = ConsensusError::InvalidSignature.to_string();
    let job = match helios_check_steps::step1(update, slot, store, genesis_root, forks, keys, &|| 0) {
        Ok((job, _)) => job,
        Err(Refusal::Rules(e)) => return Err(e),
        Err(Refusal::Signature(_)) => return Err(invalid_signature),
        Err(Refusal::Keys(e)) => return Err(format!("keys: {e}")),
    };
    let miller = helios_check_steps::step2(&job).expect("step 2 takes step 1's job");
    match helios_check_steps::step3(&miller).expect("step 3 takes step 2's output") {
        true => Ok(()),
        false => Err(invalid_signature),
    }
}

/// The keys whoever submits `update` supplies: the signing committee's
/// aggregate key, then each non-signer's, uncompressed. `None` when the store
/// has no signing committee (Helios refuses the update for its period).
pub fn supplied_keys<S: ConsensusSpec>(update: &GenericUpdate<S>, store: &LightClientStore<S>) -> Option<Vec<u8>> {
    let store_period = calc_sync_period::<S>(store.finalized_header.beacon().slot);
    let committee = if calc_sync_period::<S>(update.signature_slot) == store_period {
        &store.current_sync_committee
    } else {
        store.next_sync_committee.as_ref()?
    };
    let uncompressed = |k: &PublicKey| blst::min_pk::PublicKey::key_validate(&k.as_ssz_bytes()).unwrap().serialize();
    let mut keys = uncompressed(&committee.aggregate_pubkey).to_vec();
    for (i, signed) in update.sync_aggregate.sync_committee_bits.iter().enumerate() {
        if !signed {
            keys.extend(uncompressed(&committee.pubkeys[i]));
        }
    }
    Some(keys)
}

// ---------------------------------------------------------------------------
// consensus-specs sync tests

/// A light-client header as a sync test step checks it.
#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub slot: u64,
    pub beacon_root: B256,
    pub execution_root: B256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Checks {
    pub finalized_header: Check,
    pub optimistic_header: Check,
}

pub enum SpecStep {
    Update { name: String, ssz: Vec<u8>, current_slot: u64, valid: bool, checks: Option<Checks> },
    ForceUpdate { current_slot: u64, checks: Checks },
    UpgradeStore { checks: Checks },
}

/// A consensus-specs light-client sync test (minimal preset), read the way
/// Helios's own test runner reads it.
pub struct SpecCase {
    pub name: String,
    pub bootstrap: Vec<u8>,
    pub trusted_block_root: B256,
    pub genesis_root: B256,
    /// `Forks` as JSON, which either side's type reads.
    pub forks: Value,
    pub steps: Vec<SpecStep>,
}

fn snappy(path: &Path) -> Vec<u8> {
    snap::raw::Decoder::new().decompress_vec(&std::fs::read(path).unwrap()).unwrap()
}

impl SpecCase {
    pub fn load(dir: &Path, name: String) -> SpecCase {
        #[derive(Deserialize)]
        struct Meta {
            genesis_validators_root: B256,
            trusted_block_root: B256,
        }
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
        let meta: Meta = serde_yaml::from_str(&read("meta.yaml")).unwrap();
        let steps: Vec<serde_yaml::Mapping> = serde_yaml::from_str(&read("steps.yaml")).unwrap();
        let steps = steps
            .into_iter()
            .map(|step| {
                let (kind, body) = step.into_iter().next().unwrap();
                let current_slot = || body["current_slot"].as_u64().unwrap();
                let checks = || body.get("checks").map(|c| serde_yaml::from_value::<Checks>(c.clone()).unwrap());
                match kind.as_str().unwrap() {
                    "process_update" => {
                        let name = body["update"].as_str().unwrap().to_string();
                        SpecStep::Update {
                            ssz: snappy(&dir.join(format!("{name}.ssz_snappy"))),
                            current_slot: current_slot(),
                            valid: body.get("valid").and_then(serde_yaml::Value::as_bool).unwrap_or(true),
                            checks: checks(),
                            name,
                        }
                    }
                    "force_update" => SpecStep::ForceUpdate { current_slot: current_slot(), checks: checks().unwrap() },
                    "upgrade_store" => SpecStep::UpgradeStore { checks: checks().unwrap() },
                    other => panic!("{name}: unknown step {other}"),
                }
            })
            .collect();
        SpecCase {
            bootstrap: snappy(&dir.join("bootstrap.ssz_snappy")),
            trusted_block_root: meta.trusted_block_root,
            genesis_root: meta.genesis_validators_root,
            forks: serde_json::to_value(spec_forks(dir)).unwrap(),
            steps,
            name,
        }
    }
}

/// The forks a sync test runs under: its config.yaml over the minimal
/// preset's defaults, as Helios's test runner reads them.
fn spec_forks(dir: &Path) -> Forks {
    use serde_yaml::Value::{Number, String};
    let fork = |epoch: u64, version: u32| Fork { epoch, fork_version: version.to_be_bytes().into() };
    let mut forks = Forks {
        genesis: fork(0, 0x00000001),
        altair: fork(0, 0x01000001),
        bellatrix: fork(0, 0x02000001),
        capella: fork(0, 0x03000001),
        deneb: fork(u64::MAX, 0x04000001),
        electra: fork(u64::MAX, 0x05000001),
        fulu: fork(u64::MAX, 0x06000001),
        gloas: fork(u64::MAX, 0x07000001),
    };
    let Ok(raw) = std::fs::read_to_string(dir.join("config.yaml")) else { return forks };
    let config: serde_yaml::Mapping = serde_yaml::from_str(&raw).unwrap();
    let version = |name: &str| {
        config.get(format!("{name}_FORK_VERSION").as_str()).map(|v| match v {
            Number(n) => n.as_u64().unwrap() as u32,
            String(s) => u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap(),
            v => panic!("fork version {v:?}"),
        })
    };
    let epoch = |name: &str| {
        config.get(format!("{name}_FORK_EPOCH").as_str()).map(|v| match v {
            Number(n) => n.as_u64().unwrap(),
            String(s) => s.parse().unwrap(),
            v => panic!("fork epoch {v:?}"),
        })
    };
    if let Some(v) = version("GENESIS") {
        forks.genesis.fork_version = v.to_be_bytes().into();
    }
    for (name, f) in [
        ("ALTAIR", &mut forks.altair),
        ("BELLATRIX", &mut forks.bellatrix),
        ("CAPELLA", &mut forks.capella),
        ("DENEB", &mut forks.deneb),
        ("ELECTRA", &mut forks.electra),
        ("FULU", &mut forks.fulu),
        ("GLOAS", &mut forks.gloas),
    ] {
        if let (Some(e), Some(v)) = (epoch(name), version(name)) {
            *f = fork(e, v);
        }
    }
    forks
}

// ---------------------------------------------------------------------------
// Mainnet fixtures

pub fn mainnet_genesis_root() -> B256 {
    b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
}

/// Mainnet's forks (as the host's `mainnet_forks`).
pub fn mainnet_forks() -> Forks {
    let f = |epoch, v: [u8; 4]| Fork { epoch, fork_version: v.into() };
    Forks {
        genesis: f(0, [0, 0, 0, 0]),
        altair: f(74240, [1, 0, 0, 0]),
        bellatrix: f(144896, [2, 0, 0, 0]),
        capella: f(194048, [3, 0, 0, 0]),
        deneb: f(269568, [4, 0, 0, 0]),
        electra: f(364032, [5, 0, 0, 0]),
        fulu: f(411392, [6, 0, 0, 0]),
        gloas: f(u64::MAX, [7, 0, 0, 0]),
    }
}

/// `fixtures/mainnet-now`, beacon-API JSON (`data`).
pub struct Fixtures {
    pub bootstrap: Value,
    pub update: Value,
    pub finality: Value,
    /// The best update of each of the last ten periods (1899-1908).
    pub last10: Vec<Value>,
}

impl Fixtures {
    pub fn load() -> Fixtures {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/mainnet-now");
        let read = |f: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap();
        let data = |v: &Value| v["data"].clone();
        Fixtures {
            bootstrap: data(&read("bootstrap.json")),
            update: data(&read("updates.json")[0]),
            finality: data(&read("finality.json")),
            last10: read("updates-last10.json").as_array().unwrap().iter().map(data).collect(),
        }
    }
}

/// Where a mainnet case's store comes from.
#[derive(Clone)]
pub enum StoreSpec {
    /// The fixture bootstrap, with these updates (JSON, is a finality update) applied.
    Bootstrap { bootstrap: Value, applied: Vec<(Value, bool)> },
    /// What a light client holds after the previous period's update (JSON): its
    /// attested header as the finalized header and its next committee, which
    /// signs this period's update.
    AfterUpdate(Value),
}

pub struct MainnetCase {
    pub name: String,
    pub store: StoreSpec,
    /// Replaces the store's signing committee (SSZ), for a re-signed update.
    pub signing_committee: Option<Vec<u8>>,
    /// Beacon-API JSON.
    pub update: Value,
    pub finality: bool,
    pub current_slot: u64,
    /// Whether the update should verify (tampered copies should not).
    pub valid: bool,
}

fn signature_slot(update: &Value) -> u64 {
    update["signature_slot"].as_str().unwrap().parse().unwrap()
}

fn period(update: &Value) -> u64 {
    signature_slot(update) / 8192
}

/// The real updates, each with the store it applies to: the period-1908
/// update from the bootstrap, the finality update after it, and each of the
/// last ten periods' updates after the one before.
fn real_updates(f: &Fixtures) -> Vec<(String, StoreSpec, Value, bool)> {
    let bootstrap = |applied| StoreSpec::Bootstrap { bootstrap: f.bootstrap.clone(), applied };
    let mut out = vec![
        (format!("period {} update, from the bootstrap", period(&f.update)), bootstrap(vec![]), f.update.clone(), false),
        (
            format!("period {} finality update, after that update", period(&f.finality)),
            bootstrap(vec![(f.update.clone(), false)]),
            f.finality.clone(),
            true,
        ),
    ];
    for pair in f.last10.windows(2) {
        out.push((
            format!("period {} update, after period {}'s", period(&pair[1]), period(&pair[0])),
            StoreSpec::AfterUpdate(pair[0].clone()),
            pair[1].clone(),
            false,
        ));
    }
    out
}

fn current_slot(f: &Fixtures) -> u64 {
    [&f.update, &f.finality].into_iter().chain(&f.last10).map(signature_slot).max().unwrap() + 10
}

fn flip_hex_byte(v: &mut Value, byte: usize, mask: u8) {
    let mut b = hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    b[byte] ^= mask;
    *v = json!(format!("0x{}", hex::encode(b)));
}

/// Tampered copies of a valid update, none of which may verify.
fn tampered(update: &Value, finality: bool, other_committees: &[Value]) -> Vec<(&'static str, Value)> {
    let mut out = Vec::new();
    let mut copy = |what, change: &dyn Fn(&mut Value)| {
        let mut u = update.clone();
        change(&mut u);
        out.push((what, u));
    };
    copy("a signature byte changed", &|u| flip_hex_byte(&mut u["sync_aggregate"]["sync_committee_signature"], 95, 1));
    copy("the identity as the signature", &|u| {
        u["sync_aggregate"]["sync_committee_signature"] = json!(format!("0xc0{}", "00".repeat(95)))
    });
    copy("a participation bit flipped", &|u| flip_hex_byte(&mut u["sync_aggregate"]["sync_committee_bits"], 0, 0x80));
    copy("a finality branch node changed", &|u| flip_hex_byte(&mut u["finality_branch"][0], 0, 1));
    if !finality {
        copy("a next committee branch node changed", &|u| flip_hex_byte(&mut u["next_sync_committee_branch"][0], 0, 1));
        let other = other_committees.iter().find(|c| **c != update["next_sync_committee"]).unwrap().clone();
        copy("another next committee", &|u| u["next_sync_committee"] = other.clone());
    }
    out
}

/// The real mainnet updates, and tampered copies of each.
pub fn mainnet_cases(f: &Fixtures) -> Vec<MainnetCase> {
    let now = current_slot(f);
    let other_committees = [f.bootstrap["current_sync_committee"].clone(), f.last10[0]["next_sync_committee"].clone()];
    let mut out = Vec::new();
    for (name, store, update, finality) in real_updates(f) {
        let case = |name: String, update: Value, valid| MainnetCase {
            name,
            store: store.clone(),
            signing_committee: None,
            update,
            finality,
            current_slot: now,
            valid,
        };
        out.push(case(name.clone(), update.clone(), true));
        for (what, copy) in tampered(&update, finality, &other_committees) {
            out.push(case(format!("{name}, {what}"), copy, false));
        }
    }
    out
}

/// A generated 512-key committee, which re-signs real updates with chosen
/// members not signing.
pub struct Generated {
    secret: Vec<blst::min_pk::SecretKey>,
    /// The committee, SSZ.
    pub ssz: Vec<u8>,
}

impl Default for Generated {
    fn default() -> Self {
        use blst::min_pk::{AggregatePublicKey, PublicKey, SecretKey};
        let secret: Vec<SecretKey> = (0..512u32)
            .map(|i| {
                let mut ikm = [0x5e; 32];
                ikm[..4].copy_from_slice(&i.to_le_bytes());
                SecretKey::key_gen(&ikm, &[]).unwrap()
            })
            .collect();
        let public: Vec<PublicKey> = secret.iter().map(SecretKey::sk_to_pk).collect();
        let aggregate = AggregatePublicKey::aggregate(&public.iter().collect::<Vec<_>>(), false).unwrap().to_public_key();
        let ssz = public.iter().chain([&aggregate]).flat_map(|k| k.compress()).collect();
        Generated { secret, ssz }
    }
}

impl Generated {
    /// `update` signed by the members `absent` leaves out.
    pub fn resign(&self, update: &Value, finality: bool, absent: impl Fn(usize) -> bool) -> Value {
        use sha2::{Digest, Sha256};
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let sha = |a: &[u8], b: &[u8]| -> [u8; 32] { Sha256::new().chain_update(a).chain_update(b).finalize().into() };
        let typed: GenericUpdate<MainnetConsensusSpec> = if finality {
            GenericUpdate::from(&serde_json::from_value::<FinalityUpdate<MainnetConsensusSpec>>(update.clone()).unwrap())
        } else {
            GenericUpdate::from(&serde_json::from_value::<Update<MainnetConsensusSpec>>(update.clone()).unwrap())
        };
        // The sync committee's signing root (consensus-specs compute_signing_root,
        // DOMAIN_SYNC_COMMITTEE, the fork of the slot before the signature slot).
        let epoch = typed.signature_slot.saturating_sub(1) / 32;
        let forks = mainnet_forks();
        let version = [&forks.gloas, &forks.fulu, &forks.electra, &forks.deneb, &forks.capella, &forks.bellatrix, &forks.altair, &forks.genesis]
            .into_iter()
            .find(|f| epoch >= f.epoch)
            .unwrap()
            .fork_version;
        let mut padded = [0u8; 32];
        padded[..4].copy_from_slice(version.as_slice());
        let fork_data_root = sha(&padded, mainnet_genesis_root().as_slice());
        let mut domain = [0u8; 32];
        domain[0] = 7;
        domain[4..].copy_from_slice(&fork_data_root[..28]);
        let root = sha(typed.attested_header.beacon().tree_hash_root().as_slice(), &domain);

        let signatures: Vec<blst::min_pk::Signature> =
            (0..512).filter(|&i| !absent(i)).map(|i| self.secret[i].sign(&root, DST, &[])).collect();
        let signature = blst::min_pk::AggregateSignature::aggregate(&signatures.iter().collect::<Vec<_>>(), false)
            .unwrap()
            .to_signature();
        let mut bits = [0u8; 64];
        for i in (0..512).filter(|&i| !absent(i)) {
            bits[i / 8] |= 1 << (i % 8);
        }
        let mut out = update.clone();
        out["sync_aggregate"]["sync_committee_bits"] = json!(format!("0x{}", hex::encode(bits)));
        out["sync_aggregate"]["sync_committee_signature"] = json!(format!("0x{}", hex::encode(signature.compress())));
        out
    }
}

/// The period-1908 update and finality update, re-signed by a generated
/// committee with 0, 17 and 170 members not signing (170 is the most the 2/3
/// supermajority allows), and at 170 with one more participation bit flipped.
pub fn non_signer_cases(f: &Fixtures, g: &Generated) -> Vec<MainnetCase> {
    let now = current_slot(f);
    let mut out = Vec::new();
    for (name, store, update, finality) in real_updates(f).into_iter().take(2) {
        let case = |name: String, update: Value, valid| MainnetCase {
            name,
            store: store.clone(),
            signing_committee: Some(g.ssz.clone()),
            update,
            finality,
            current_slot: now,
            valid,
        };
        for k in [0usize, 17, 170] {
            // Members 2, 5, 8, ... don't sign: k of them.
            let resigned = g.resign(&update, finality, |i| i % 3 == 2 && i / 3 < k);
            out.push(case(format!("{name}, re-signed with {k} non-signers"), resigned.clone(), true));
            if k == 170 {
                let mut flipped = resigned;
                flip_hex_byte(&mut flipped["sync_aggregate"]["sync_committee_bits"], 0, 1);
                out.push(case(format!("{name}, re-signed with {k} non-signers, a participation bit flipped"), flipped, false));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The two sides

macro_rules! side {
    ($m:ident, $helios:ident, $split:path, $doc:literal) => {
        #[doc = $doc]
        pub mod $m {
            use super::{mainnet_genesis_root, Check, MainnetCase, Record, Snapshot, SpecCase, SpecStep, StoreSpec, Verdict};
            use alloy_primitives::B256;
            use serde_json::Value;
            use ssz::Decode;
            use tree_hash::TreeHash;
            use $helios::{
                apply_bootstrap, apply_generic_update, calc_sync_period,
                consensus_spec::{ConsensusSpec, MainnetConsensusSpec, MinimalConsensusSpec},
                force_update,
                types::{
                    Bootstrap, FinalityUpdate, Forks, GenericUpdate, LightClientHeader, LightClientStore, OptimisticUpdate,
                    SyncCommittee, Update,
                },
                verify_bootstrap, verify_generic_update,
            };

            fn snapshot<S: ConsensusSpec>(store: &LightClientStore<S>) -> Snapshot {
                let header = |h: &LightClientHeader| (h.beacon().slot, h.beacon().tree_hash_root().0);
                Snapshot {
                    finalized: header(&store.finalized_header),
                    optimistic: header(&store.optimistic_header),
                    next_committee: store.next_sync_committee.as_ref().map(|c| c.tree_hash_root().0),
                }
            }

            fn verdicts<S: ConsensusSpec>(
                update: &GenericUpdate<S>,
                slot: u64,
                store: &LightClientStore<S>,
                genesis_root: B256,
                forks: &Forks,
            ) -> Vec<(&'static str, Verdict)> {
                let helios = verify_generic_update::<S>(update, slot, store, genesis_root, forks).map_err(|e| e.to_string());
                let mut out = vec![("Helios", helios)];
                out.extend($split(update, slot, store, genesis_root, forks));
                out
            }

            fn check(expected: &Check, header: &LightClientHeader, what: &str) {
                let actual = (header.beacon().slot, header.beacon().tree_hash_root(), header.execution_root());
                assert_eq!(actual, (expected.slot, expected.beacon_root, expected.execution_root), "{what}");
            }

            fn decode_update<S: ConsensusSpec>(ssz: &[u8]) -> GenericUpdate<S> {
                if let Ok(u) = Update::<S>::from_ssz_bytes(ssz) {
                    return GenericUpdate::from(&u);
                }
                if let Ok(u) = FinalityUpdate::<S>::from_ssz_bytes(ssz) {
                    return GenericUpdate::from(&u);
                }
                GenericUpdate::from(&OptimisticUpdate::<S>::from_ssz_bytes(ssz).expect("an update"))
            }

            /// A consensus-specs sync test, step by step, as Helios's runner
            /// runs it: a valid update is applied, and the headers checked.
            pub fn spec(case: &SpecCase) -> Vec<Record> {
                type S = MinimalConsensusSpec;
                let forks: Forks = serde_json::from_value(case.forks.clone()).unwrap();
                let bootstrap = Bootstrap::<S>::from_ssz_bytes(&case.bootstrap).expect("a bootstrap");
                verify_bootstrap(&bootstrap, case.trusted_block_root, &forks).expect("the bootstrap verifies");
                let mut store = LightClientStore::<S>::default();
                apply_bootstrap(&mut store, &bootstrap);
                let mut out = Vec::new();
                for step in &case.steps {
                    let (what, checks) = match step {
                        SpecStep::Update { name, ssz, current_slot, valid, checks } => {
                            let what = format!("{}: {name}", case.name);
                            let update = decode_update::<S>(ssz);
                            let verdicts = verdicts(&update, *current_slot, &store, case.genesis_root, &forks);
                            assert_eq!(verdicts[0].1.is_ok(), *valid, "{what}: Helios's verdict is not the test's");
                            if *valid {
                                let _ = apply_generic_update::<S>(&mut store, &update);
                            }
                            out.push(Record { case: what.clone(), verdicts, store: snapshot(&store) });
                            (what, checks.as_ref())
                        }
                        SpecStep::ForceUpdate { current_slot, checks } => {
                            let what = format!("{}: force update at slot {current_slot}", case.name);
                            let _ = force_update(&mut store, *current_slot);
                            out.push(Record { case: what.clone(), verdicts: vec![], store: snapshot(&store) });
                            (what, Some(checks))
                        }
                        SpecStep::UpgradeStore { checks } => (format!("{}: upgrade store", case.name), Some(checks)),
                    };
                    if let Some(c) = checks {
                        check(&c.finalized_header, &store.finalized_header, &format!("{what}: finalized header"));
                        check(&c.optimistic_header, &store.optimistic_header, &format!("{what}: optimistic header"));
                    }
                }
                out
            }

            fn generic<S: ConsensusSpec>(update: &Value, finality: bool) -> GenericUpdate<S> {
                if finality {
                    GenericUpdate::from(&serde_json::from_value::<FinalityUpdate<S>>(update.clone()).unwrap())
                } else {
                    GenericUpdate::from(&serde_json::from_value::<Update<S>>(update.clone()).unwrap())
                }
            }

            fn forks() -> Forks {
                serde_json::from_value(serde_json::to_value(super::mainnet_forks()).unwrap()).unwrap()
            }

            /// A mainnet case's update.
            pub fn update(case: &MainnetCase) -> GenericUpdate<MainnetConsensusSpec> {
                generic(&case.update, case.finality)
            }

            /// The store a mainnet case's update verifies against.
            pub fn store(case: &MainnetCase) -> LightClientStore<MainnetConsensusSpec> {
                type S = MainnetConsensusSpec;
                let mut store = match &case.store {
                    StoreSpec::Bootstrap { bootstrap, applied } => {
                        let b: Bootstrap<S> = serde_json::from_value(bootstrap.clone()).unwrap();
                        verify_bootstrap(&b, b.header().beacon().tree_hash_root(), &forks()).expect("the bootstrap verifies");
                        let mut store = LightClientStore::<S>::default();
                        apply_bootstrap(&mut store, &b);
                        for (u, finality) in applied {
                            let _ = apply_generic_update::<S>(&mut store, &generic(u, *finality));
                        }
                        store
                    }
                    StoreSpec::AfterUpdate(previous) => {
                        let p: Update<S> = serde_json::from_value(previous.clone()).unwrap();
                        LightClientStore {
                            finalized_header: p.attested_header().clone(),
                            optimistic_header: p.attested_header().clone(),
                            current_sync_committee: p.next_sync_committee().clone(),
                            next_sync_committee: Some(p.next_sync_committee().clone()),
                            ..Default::default()
                        }
                    }
                };
                if let Some(ssz) = &case.signing_committee {
                    let committee = SyncCommittee::<S>::from_ssz_bytes(ssz).unwrap();
                    let store_period = calc_sync_period::<S>(store.finalized_header.beacon().slot);
                    if calc_sync_period::<S>(update(case).signature_slot) == store_period {
                        store.current_sync_committee = committee;
                    } else {
                        store.next_sync_committee = Some(committee);
                    }
                }
                store
            }

            /// Each mainnet case's verdicts.
            pub fn mainnet(cases: &[MainnetCase]) -> Vec<Record> {
                cases
                    .iter()
                    .map(|c| {
                        let store = store(c);
                        let verdicts = verdicts(&update(c), c.current_slot, &store, mainnet_genesis_root(), &forks());
                        Record { case: c.name.clone(), verdicts, store: snapshot(&store) }
                    })
                    .collect()
            }
        }
    };
}

side!(upstream, helios_upstream, super::no_split, "Unpatched Helios: a16z/helios at the pinned commit.");
side!(patched, helios_consensus_core, super::split, "Patched Helios, and the three steps.");
