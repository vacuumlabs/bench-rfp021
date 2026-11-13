//! `step-inputs <fixture dir> <out dir>`: chain the three update steps in the
//! executor (step 1's job feeds step 2, its Miller output feeds step 3) and save
//! each step's input for proving. Also saves inclusion inputs.
//! `nonsigners <fixture dir>`: the same three steps on the fixture updates
//! re-signed by a generated committee with 0, 17 and 170 non-signers, with the
//! signers' keys decompressed and supplied uncompressed.
//! `prove <step1|step2|step3|inclusion> <input.bin>`: real-prove one input.
use std::{fs, path::Path, time::Instant};

use alloy_primitives::{b256, B256};
use helios_check_methods::{INCLUSION_ELF, INCLUSION_ID, STEP1_ELF, STEP1_ID, STEP2_ELF, STEP2_ID, STEP3_ELF, STEP3_ID};
use helios_check_steps::{Job, Miller, Step1In};
use helios_consensus_core::{
    apply_bootstrap, calc_sync_period,
    consensus_spec::MainnetConsensusSpec as S,
    types::{Bootstrap, FinalityUpdate, LightClientStore, SyncCommittee, Update},
    verify_bootstrap, verify_finality_update, verify_update,
};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv};
use serde::Serialize;
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

fn words<T: Serialize>(v: &T) -> Vec<u8> {
    risc0_zkvm::serde::to_vec(v).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn exec(elf: &[u8], input: &[u8]) -> (risc0_zkvm::Journal, u64, u64) {
    // Step 1 with 170 non-signers decompressed runs to about 80M cycles.
    let env = ExecutorEnv::builder().write_slice(input).session_limit(Some(1 << 32)).build().unwrap();
    let info = default_executor().execute(env, elf).expect("execute");
    let user = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    (info.journal, user, padded)
}

/// A fixture update as step 1 receives it, and the store it applies to.
struct Case {
    name: &'static str,
    input: Step1In,
    store: LightClientStore<S>,
    /// The update's beacon-API JSON (`data`).
    update: Value,
}

/// The handoff update, from the bootstrap's store, then the finality update,
/// after the handoff update has been applied.
fn cases(dir: &str) -> Vec<Case> {
    let read = |n: &str| fs::read_to_string(Path::new(dir).join(n)).unwrap();
    let bootstrap: Bootstrap<S> = serde_json::from_value(serde_json::from_str::<Value>(&read("bootstrap.json")).unwrap()["data"].clone()).unwrap();
    let forks = super::mainnet_forks();
    let genesis_root = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
    verify_bootstrap(&bootstrap, bootstrap.header().beacon().tree_hash_root(), &forks).unwrap();
    let mut store = LightClientStore::<S>::default();
    apply_bootstrap(&mut store, &bootstrap);
    let updates: Vec<Value> = serde_json::from_str(&read("updates.json")).unwrap();
    let finality: Value = serde_json::from_str::<Value>(&read("finality.json")).unwrap()["data"].clone();
    let now: u64 = finality["signature_slot"].as_str().unwrap().parse::<u64>().unwrap() + 10;

    let mut out = Vec::new();
    for (name, update, is_fin) in [("handoff", updates[0]["data"].clone(), false), ("finality_only", finality.clone(), true)] {
        // Finality-only runs after the handoff update has been applied.
        if is_fin {
            let u = serde_json::from_value(updates[0]["data"].clone()).unwrap();
            helios_consensus_core::apply_update(&mut store, &u);
        }
        let input = Step1In {
            finalized_header_json: serde_json::to_string(&store.finalized_header).unwrap(),
            current_committee_ssz: store.current_sync_committee.as_ssz_bytes(),
            next_committee_ssz: store.next_sync_committee.as_ref().map(|c| c.as_ssz_bytes()),
            update_json: update.to_string(),
            is_finality_update: is_fin,
            expected_current_slot: now,
            genesis_root: genesis_root.0,
            forks_json: serde_json::to_string(&forks).unwrap(),
            supplied_keys: None,
        };
        out.push(Case { name, input, store: store.clone(), update });
    }
    out
}

/// One step's run: its input, in-guest counters, session user and padded cycles.
type StepRun = (Vec<u8>, Vec<(String, u64)>, u64, u64);

/// Run the three steps in the executor, each fed the previous one's output.
/// Step 3 fails unless the signature verifies.
fn chain(s1: &Step1In) -> [StepRun; 3] {
    let in1 = words(s1);
    let (j1, u1, p1) = exec(STEP1_ELF, &in1);
    let (job, c1): (Job, Vec<(String, u64)>) = j1.decode().unwrap();
    let in2 = words(&job);
    let (j2, u2, p2) = exec(STEP2_ELF, &in2);
    let (miller, c2): (Miller, Vec<(String, u64)>) = j2.decode().unwrap();
    let in3 = words(&miller);
    let (j3, u3, p3) = exec(STEP3_ELF, &in3);
    let (ok, c3): (bool, Vec<(String, u64)>) = j3.decode().unwrap();
    assert!(ok);
    [(in1, c1, u1, p1), (in2, c2, u2, p2), (in3, c3, u3, p3)]
}

pub fn make_inputs(dir: &str, out: &str) {
    fs::create_dir_all(out).unwrap();
    let mut rows = vec!["case,step,metric,value".to_string()];
    for c in cases(dir) {
        let case = c.name;
        for (i, (input, cs, u, p)) in chain(&c.input).iter().enumerate() {
            let n = i + 1;
            fs::write(format!("{out}/{case}_step{n}.bin"), input).unwrap();
            println!("{case} step{n}: input {} B, session user={u} padded={p} {cs:?}", input.len());
            for (k, v) in cs.iter() {
                rows.push(format!("{case},step{n},{k},{v}"));
            }
            rows.push(format!("{case},step{n},session_user_cycles,{u}"));
            rows.push(format!("{case},step{n},session_padded_cycles,{p}"));
            rows.push(format!("{case},step{n},input_bytes,{}", input.len()));
        }
    }
    for (tx, log) in [(250usize, 0u32), (194, 21)] {
        let (bytes, label) = super::inclusion::input(dir, tx, log);
        fs::write(format!("{out}/inclusion_{label}.bin"), &bytes).unwrap();
        println!("inclusion {label}: input {} B", bytes.len());
    }
    fs::write("results/steps.csv", rows.join("\n") + "\n").unwrap();
    println!("wrote results/steps.csv and inputs in {out}");
}

/// Mainnet updates have 0-2 non-signers, so they never show what non-signers
/// cost. Each fixture update keeps its headers and branches but is re-signed
/// by a generated 512-key committee, which replaces the store's signing
/// committee, with 0, 17 and 170 members not signing (170 is the most the
/// 2/3 supermajority allows: 342 * 3 >= 512 * 2). Helios must accept each
/// re-signed update natively, and step 3 must accept its signature. Step 1
/// runs twice: decompressing the keys it aggregates, and with them supplied.
pub fn nonsigners(dir: &str) {
    use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    let secret: Vec<SecretKey> = (0..512u32)
        .map(|i| {
            let mut ikm = [0x5e; 32];
            ikm[..4].copy_from_slice(&i.to_le_bytes());
            SecretKey::key_gen(&ikm, &[]).unwrap()
        })
        .collect();
    let public: Vec<PublicKey> = secret.iter().map(SecretKey::sk_to_pk).collect();
    let aggregate = AggregatePublicKey::aggregate(&public.iter().collect::<Vec<_>>(), false).unwrap().to_public_key();
    let committee_ssz: Vec<u8> = public.iter().chain([&aggregate]).flat_map(|k| k.compress()).collect();
    let committee = SyncCommittee::<S>::from_ssz_bytes(&committee_ssz).unwrap();
    let forks = super::mainnet_forks();

    let mut rows = vec!["case,nonsigners,keys,step,metric,value".to_string()];
    let mut table = Vec::new();
    for c in cases(dir) {
        let genesis_root = B256::from(c.input.genesis_root);
        let now = c.input.expected_current_slot;
        let sig_slot: u64 = c.update["signature_slot"].as_str().unwrap().parse().unwrap();
        let attested = if c.input.is_finality_update {
            serde_json::from_value::<FinalityUpdate<S>>(c.update.clone()).unwrap().attested_header().beacon().tree_hash_root()
        } else {
            serde_json::from_value::<Update<S>>(c.update.clone()).unwrap().attested_header().beacon().tree_hash_root()
        };
        let root = super::signing_root(attested, super::fork_version(&forks, sig_slot.saturating_sub(1)), genesis_root);
        let signs_with_current = calc_sync_period::<S>(sig_slot) == calc_sync_period::<S>(c.store.finalized_header.beacon().slot);

        for k in [0usize, 17, 170] {
            // Members 2, 5, 8, ... don't sign: k of them.
            let absent = |i: usize| i % 3 == 2 && i / 3 < k;
            let signatures: Vec<Signature> = (0..512).filter(|&i| !absent(i)).map(|i| secret[i].sign(&root, DST, &[])).collect();
            let signature = AggregateSignature::aggregate(&signatures.iter().collect::<Vec<_>>(), false).unwrap().to_signature();
            let mut bits = [0u8; 64];
            for i in (0..512).filter(|&i| !absent(i)) {
                bits[i / 8] |= 1 << (i % 8);
            }
            let mut update = c.update.clone();
            update["sync_aggregate"]["sync_committee_bits"] = json!(format!("0x{}", hex::encode(bits)));
            update["sync_aggregate"]["sync_committee_signature"] = json!(format!("0x{}", hex::encode(signature.compress())));

            let mut store = c.store.clone();
            let mut input = c.input.clone();
            input.update_json = update.to_string();
            if signs_with_current {
                store.current_sync_committee = committee.clone();
                input.current_committee_ssz = committee_ssz.clone();
            } else {
                store.next_sync_committee = Some(committee.clone());
                input.next_committee_ssz = Some(committee_ssz.clone());
            }
            let verdict = if c.input.is_finality_update {
                verify_finality_update(&serde_json::from_value(update).unwrap(), now, &store, genesis_root, &forks)
            } else {
                verify_update(&serde_json::from_value(update).unwrap(), now, &store, genesis_root, &forks)
            };
            verdict.expect("Helios accepts the re-signed update");

            for supplied in [false, true] {
                let keys = if supplied { "supplied" } else { "decompressed" };
                input.supplied_keys = supplied.then(|| {
                    let absent_keys = (0..512).filter(|&i| absent(i)).flat_map(|i| public[i].serialize());
                    aggregate.serialize().into_iter().chain(absent_keys).collect()
                });
                let steps = chain(&input);
                if supplied && k == 17 {
                    refuses_wrong_keys(&input);
                }
                for (i, (bytes, cs, u, _)) in steps.iter().enumerate() {
                    let step = format!("step{}", i + 1);
                    for (m, v) in cs {
                        rows.push(format!("{},{k},{keys},{step},{m},{v}", c.name));
                    }
                    rows.push(format!("{},{k},{keys},{step},session_user_cycles,{u}", c.name));
                    rows.push(format!("{},{k},{keys},{step},input_bytes,{}", c.name, bytes.len()));
                }
                let counter = |m: &str| steps[0].1.iter().find(|(name, _)| name == m).unwrap().1;
                let work = counter("helios_rules") + counter("bls_prepare");
                let supplied_bytes = input.supplied_keys.as_ref().map_or(0, Vec::len);
                println!(
                    "{} {k:3} non-signers, keys {keys:12}: step 1 work {work}, signers' key {}, session {}; step 2 {}; step 3 {}",
                    c.name,
                    counter("signers_key"),
                    steps[0].2,
                    steps[1].2,
                    steps[2].2
                );
                table.push((c.name, k, keys, work, counter("signers_key"), supplied_bytes));
            }
        }
    }
    fs::create_dir_all("results").unwrap();
    fs::write("results/nonsigners.csv", rows.join("\n") + "\n").unwrap();

    println!("\n| Case | Non-signers | Keys | Step 1 work | of which signers' key | Keys supplied |");
    println!("|---|---|---|---|---|---|");
    for (case, k, keys, work, key, bytes) in table {
        println!("| {case} | {k} | {keys} | {work} | {key} | {bytes} B |");
    }
    println!("\nwrote results/nonsigners.csv");
}

/// Step 1 must refuse supplied keys that are not exactly the ones it needs.
/// `input` carries valid supplied keys for at least two non-signers.
fn refuses_wrong_keys(input: &Step1In) {
    let keys = input.supplied_keys.as_ref().unwrap();
    let refused = |bad_keys: Vec<u8>, what: &str| {
        let mut bad = input.clone();
        bad.supplied_keys = Some(bad_keys);
        let env = ExecutorEnv::builder().write_slice(&words(&bad)).build().unwrap();
        assert!(default_executor().execute(env, STEP1_ELF).is_err(), "step 1 accepted {what}");
    };
    // Keys: the aggregate key, then each non-signer's.
    let mut swapped = keys.clone();
    swapped.copy_within(96..192, 192);
    refused(swapped, "another member's key");
    let mut off_curve = keys.clone();
    off_curve[95] ^= 1;
    refused(off_curve, "a point off the curve");
    refused(keys[..keys.len() - 96].to_vec(), "one key too few");
    let mut extra = keys.clone();
    extra.extend_from_slice(&keys[96..192]);
    refused(extra, "one key too many");
    println!("step 1 refuses another member's key, a point off the curve, one key too few and one too many");
}

pub fn prove(which: &str, input: &str) {
    let (elf, id) = match which {
        "step1" => (STEP1_ELF, STEP1_ID),
        "step2" => (STEP2_ELF, STEP2_ID),
        "step3" => (STEP3_ELF, STEP3_ID),
        "inclusion" => (INCLUSION_ELF, INCLUSION_ID),
        _ => panic!("unknown program"),
    };
    let bytes = fs::read(input).unwrap();
    let env = ExecutorEnv::builder().write_slice(&bytes).build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove(env, elf).expect("prove");
    let prove_s = t.elapsed().as_secs_f64();
    info.receipt.verify(id).expect("verify");
    let st = &info.stats;
    let size = bincode_len(&info.receipt);
    println!(
        "PROVED {which} {input} total_cycles={} user_cycles={} segments={} prove_s={prove_s:.1} receipt_bytes={size}",
        st.total_cycles, st.user_cycles, st.segments
    );
}

fn bincode_len(r: &risc0_zkvm::Receipt) -> usize {
    risc0_zkvm::serde::to_vec(r).unwrap().len() * 4
}
