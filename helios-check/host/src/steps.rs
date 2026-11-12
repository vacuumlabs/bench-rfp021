//! `step-inputs <fixture dir> <out dir>`: chain the three update steps in the
//! executor (step 1's job feeds step 2, its Miller output feeds step 3) and save
//! each step's input for proving. Also saves inclusion inputs.
//! `prove <step1|step2|step3|inclusion> <input.bin>`: real-prove one input.
use std::{fs, path::Path, time::Instant};

use alloy_primitives::b256;
use helios_check_methods::{INCLUSION_ELF, INCLUSION_ID, STEP1_ELF, STEP1_ID, STEP2_ELF, STEP2_ID, STEP3_ELF, STEP3_ID};
use helios_check_steps::{Job, Miller, Step1In};
use helios_consensus_core::{
    apply_bootstrap, consensus_spec::MainnetConsensusSpec as S,
    types::{Bootstrap, LightClientStore},
    verify_bootstrap,
};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv};
use serde::Serialize;
use serde_json::Value;
use ssz::Encode;
use tree_hash::TreeHash;

fn words<T: Serialize>(v: &T) -> Vec<u8> {
    risc0_zkvm::serde::to_vec(v).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn exec(elf: &[u8], input: &[u8]) -> (risc0_zkvm::Journal, u64, u64) {
    let env = ExecutorEnv::builder().write_slice(input).build().unwrap();
    let info = default_executor().execute(env, elf).expect("execute");
    let user = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    (info.journal, user, padded)
}

pub fn make_inputs(dir: &str, out: &str) {
    fs::create_dir_all(out).unwrap();
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

    let mut rows = vec!["case,step,metric,value".to_string()];
    for (case, update, is_fin) in [("handoff", updates[0]["data"].clone(), false), ("finality_only", finality.clone(), true)] {
        // Finality-only runs after the handoff update has been applied.
        if is_fin {
            let u = serde_json::from_value(updates[0]["data"].clone()).unwrap();
            helios_consensus_core::apply_update(&mut store, &u);
        }
        let s1 = Step1In {
            finalized_header_json: serde_json::to_string(&store.finalized_header).unwrap(),
            current_committee_ssz: store.current_sync_committee.as_ssz_bytes(),
            next_committee_ssz: store.next_sync_committee.as_ref().map(|c| c.as_ssz_bytes()),
            update_json: update.to_string(),
            is_finality_update: is_fin,
            expected_current_slot: now,
            genesis_root: genesis_root.0,
            forks_json: serde_json::to_string(&forks).unwrap(),
        };
        let in1 = words(&s1);
        let (j1, u1, p1) = exec(STEP1_ELF, &in1);
        let (job, c1): (Job, Vec<(String, u64)>) = j1.decode().unwrap();
        let in2 = words(&job);
        let (j2, u2, p2) = exec(STEP2_ELF, &in2);
        let (miller, c2): (Miller, Vec<(String, u64)>) = j2.decode().unwrap();
        let in3 = words(&miller);
        let (j3, u3, p3) = exec(STEP3_ELF, &in3);
        let (ok, c3): (bool, Vec<(String, u64)>) = j3.decode().unwrap();
        assert!(ok);
        for (n, input, cs, u, p) in [(1, &in1, &c1, u1, p1), (2, &in2, &c2, u2, p2), (3, &in3, &c3, u3, p3)] {
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
