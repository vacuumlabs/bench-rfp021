//! Runs Helios's light-client verification on real mainnet updates inside the
//! RISC Zero executor (no proving: cycle counts are deterministic) and prints
//! where the cycles go. Usage: helios-check <helios ethereum/testdata dir>
use std::{fs, io::Write, path::PathBuf};

use alloy_primitives::{b256, fixed_bytes, B256};
use helios_check_methods::{CHECK_ELF, CHECK_ID};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update,
    consensus_spec::MainnetConsensusSpec as S,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, LightClientStore, Update},
    verify_bootstrap, verify_finality_update, verify_update,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

mod inclusion;
mod steps;

const SLOTS_PER_PERIOD: u64 = 8192;

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

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
        gloas: Fork { epoch: u64::MAX, fork_version: fixed_bytes!("07000000") },
    }
}

fn fork_version(forks: &Forks, slot: u64) -> [u8; 4] {
    let e = slot / 32;
    let all = [&forks.gloas, &forks.fulu, &forks.electra, &forks.deneb, &forks.capella, &forks.bellatrix, &forks.altair, &forks.genesis];
    all.iter().find(|f| e >= f.epoch).unwrap().fork_version.0
}

fn sha(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Sync-committee signing root, per the consensus spec (DOMAIN_SYNC_COMMITTEE = 0x07000000).
fn signing_root(header_root: B256, version: [u8; 4], genesis_root: B256) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[..4].copy_from_slice(&version);
    let fork_data_root = sha(&v, genesis_root.as_slice());
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&[7, 0, 0, 0]);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    sha(header_root.as_slice(), &domain)
}

fn hexbytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// Run the guest; returns the in-guest counters plus whole-session user/padded cycles.
fn run(input: Value) -> (Vec<(String, u64)>, u64, u64, usize) {
    let env = ExecutorEnv::builder().write(&input.to_string()).unwrap().build().unwrap();
    let info = default_executor().execute(env, CHECK_ELF).expect("execute");
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    (info.journal.decode().unwrap(), user, padded, info.segments.len())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("step-inputs") => return steps::make_inputs(&args[2], &args[3]),
        Some("prove") => return steps::prove(&args[2], &args[3]),
        Some("nonsigners") => return steps::nonsigners(&args[2]),
        _ => {}
    }
    if args.get(1).map(String::as_str) == Some("inclusion") {
        let dir = &args[2];
        let mut rows = vec!["case,metric,value".to_string()];
        for pair in args[3..].chunks(2) {
            rows.extend(inclusion::run(dir, pair[0].parse().unwrap(), pair[1].parse().unwrap()));
        }
        fs::create_dir_all("results").unwrap();
        fs::write("results/inclusion.csv", rows.join("\n") + "\n").unwrap();
        println!("wrote results/inclusion.csv");
        return;
    }
    let dir = PathBuf::from(args.get(1).expect("path to helios ethereum/testdata"));
    let read = |n: &str| fs::read_to_string(dir.join(n)).unwrap();
    let bootstrap: Bootstrap<S> = serde_json::from_str::<Data<Bootstrap<S>>>(&read("bootstrap.json")).unwrap().data;
    let updates_raw: Vec<Value> = serde_json::from_str(&read("updates.json")).unwrap();
    let finality_raw: Value = serde_json::from_str(&read("finality.json")).unwrap();
    let finality: FinalityUpdate<S> = serde_json::from_value(finality_raw["data"].clone()).unwrap();

    let forks = mainnet_forks();
    let genesis_root = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    verify_bootstrap(&bootstrap, checkpoint, &forks).expect("bootstrap");
    let mut store = LightClientStore::<S>::default();
    apply_bootstrap(&mut store, &bootstrap);
    let now = finality.signature_slot() + 10;

    println!("image id {}", hex::encode(bytemuck_id(CHECK_ID)));
    let mut rows: Vec<String> = vec!["case,attested_slot,signers,metric,cycles".into()];
    let mut cases: Vec<(String, Value, Option<Update<S>>)> = updates_raw
        .iter()
        .enumerate()
        .map(|(i, u)| (format!("update{i}_handoff"), u["data"].clone(), Some(serde_json::from_value(u["data"].clone()).unwrap())))
        .collect();
    cases.push(("finality_only".into(), finality_raw["data"].clone(), None));

    for (name, raw, update) in cases {
        let attested = update.as_ref().map(|u| u.attested_header().beacon().clone()).unwrap_or_else(|| finality.attested_header().beacon().clone());
        let sig_slot: u64 = raw["signature_slot"].as_str().unwrap().parse().unwrap();

        // Helios, unchanged.
        let full = match &update {
            Some(u) => {
                verify_update(u, now, &store, genesis_root, &forks).expect("native verify");
                json!({"Full": {"store": store, "update": u, "finality": null, "expected_current_slot": now, "genesis_root": genesis_root, "forks": forks}})
            }
            None => {
                verify_finality_update(&finality, now, &store, genesis_root, &forks).expect("native verify");
                json!({"Full": {"store": store, "update": null, "finality": finality, "expected_current_slot": now, "genesis_root": genesis_root, "forks": forks}})
            }
        };

        // Which committee signed: current if same period as the store, else next.
        let store_v = serde_json::to_value(&store).unwrap();
        let store_period = store.finalized_header.beacon().slot / SLOTS_PER_PERIOD;
        let committee = if sig_slot / SLOTS_PER_PERIOD == store_period { &store_v["current_sync_committee"] } else { &store_v["next_sync_committee"] };
        let bits = hexbytes(&raw["sync_aggregate"]["sync_committee_bits"]);
        let pubkeys = committee["pubkeys"].as_array().unwrap();
        let nonsigners: Vec<Value> = (0..512).filter(|i| bits[i / 8] >> (i % 8) & 1 == 0).map(|i| json!(hexbytes(&pubkeys[i]))).collect();
        let signers = 512 - nonsigners.len();
        let msg = signing_root(attested.tree_hash_root(), fork_version(&forks, sig_slot.saturating_sub(1)), genesis_root);
        let args = json!({
            "agg": hexbytes(&committee["aggregate_pubkey"]),
            "nonsigners": nonsigners,
            "sig": hexbytes(&raw["sync_aggregate"]["sync_committee_signature"]),
            "msg": msg.to_vec(),
        });
        let bls = json!({ "Bls": args });
        let blst = json!({ "Blst": args });

        for (input, label) in [(full, "full"), (bls, "bls"), (blst, "blst")] {
            let (counters, user, padded, segs) = run(input);
            for (k, v) in &counters {
                rows.push(format!("{name},{},{signers},{k},{v}", attested.slot));
            }
            rows.push(format!("{name},{},{signers},session_user_cycles_{label},{user}", attested.slot));
            rows.push(format!("{name},{},{signers},session_padded_cycles_{label},{padded}", attested.slot));
            println!("{name:18} {label:4} signers={signers} session user={user} padded={padded} segs={segs} {counters:?}");
        }

        // Advance the store natively, as the program's state would.
        match &update {
            Some(u) => { apply_update(&mut store, u); }
            None => { apply_finality_update(&mut store, &finality); }
        }
    }

    fs::create_dir_all("results").unwrap();
    let mut f = fs::File::create("results/cycles.csv").unwrap();
    writeln!(f, "{}", rows.join("\n")).unwrap();
    println!("wrote results/cycles.csv");
}

fn bytemuck_id(id: [u32; 8]) -> Vec<u8> {
    id.iter().flat_map(|w| w.to_le_bytes()).collect()
}
