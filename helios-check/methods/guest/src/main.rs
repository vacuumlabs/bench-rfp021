//! Cycle check: Helios `consensus-core` light-client update verification in a
//! RISC Zero 3.0.5 guest (the zkVM version LEZ v0.4.0-rc3 uses).
//!
//! Inputs arrive as JSON (Helios types use untagged serde), and only the
//! verification itself is inside the cycle counters, so parsing is excluded.
#![no_main]

use alloy_primitives::B256;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as S,
    types::{bls::Signature, FinalityUpdate, Forks, LightClientStore, Update},
    verify_finality_update, verify_update,
};
use risc0_zkvm::guest::env;
use serde::Deserialize;

risc0_zkvm::guest::entry!(main);

#[derive(Deserialize)]
enum Input {
    /// Helios's own verify_update / verify_finality_update, unchanged.
    Full {
        store: LightClientStore<S>,
        update: Option<Update<S>>,
        finality: Option<FinalityUpdate<S>>,
        expected_current_slot: u64,
        genesis_root: B256,
        forks: Forks,
    },
    /// The BLS step taken apart, with the same bls12_381 crate Helios uses.
    Bls { agg: Vec<u8>, nonsigners: Vec<Vec<u8>>, sig: Vec<u8>, msg: Vec<u8> },
    /// The same BLS step with RISC Zero's blst fork.
    Blst { agg: Vec<u8>, nonsigners: Vec<Vec<u8>>, sig: Vec<u8>, msg: Vec<u8> },
}

fn c() -> u64 {
    env::cycle_count()
}

fn g1(b: &[u8]) -> G1Affine {
    G1Affine::from_compressed(b.try_into().unwrap()).unwrap()
}

pub fn main() {
    let raw: String = env::read();
    let input: Input = serde_json::from_str(&raw).expect("input");
    let mut out: Vec<(String, u64)> = Vec::new();
    match input {
        Input::Full { store, update, finality, expected_current_slot, genesis_root, forks } => {
            let (t0, ok, t1);
            if let Some(u) = update {
                let committee = u.next_sync_committee();
                let h0 = c();
                let helios_root = tree_hash::TreeHash::tree_hash_root(committee);
                out.push(("next_committee_tree_hash".into(), c() - h0));
                // Same root computed directly over the raw key bytes (bytes extracted outside the counter).
                let v = serde_json::to_value(committee).unwrap();
                let key = |x: &serde_json::Value| -> [u8; 48] { hex_decode(x.as_str().unwrap()).try_into().unwrap() };
                let keys: Vec<[u8; 48]> = v["pubkeys"].as_array().unwrap().iter().map(key).collect();
                let agg = key(&v["aggregate_pubkey"]);
                let h1 = c();
                let direct = committee_root(&keys, &agg);
                out.push(("next_committee_direct_hash".into(), c() - h1));
                assert_eq!(direct, helios_root.0, "direct committee root differs from Helios");
                t0 = c();
                ok = verify_update(&u, expected_current_slot, &store, genesis_root, &forks).is_ok();
                t1 = c();
            } else {
                let f = finality.unwrap();
                t0 = c();
                ok = verify_finality_update(&f, expected_current_slot, &store, genesis_root, &forks).is_ok();
                t1 = c();
            }
            assert!(ok, "Helios rejected the update");
            out.push(("helios_verify_total".into(), t1 - t0));
        }
        Input::Bls { agg, nonsigners, sig, msg } => {
            // 1. Signers' key: committee aggregate minus non-signers (Helios's method).
            let t0 = c();
            let mut pk = G1Projective::from(g1(&agg));
            for n in &nonsigners {
                pk -= G1Projective::from(g1(n));
            }
            let pk = G1Affine::from(pk);
            let t1 = c();
            // 2. Signature decompression (from_compressed includes the subgroup check).
            let s = G2Affine::from_compressed(sig.as_slice().try_into().unwrap()).unwrap();
            let t2 = c();
            // 3. Helios's extra subgroup check by scalar multiplication.
            let r = Scalar::from_raw([0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48]);
            let sub_ok: bool = (s * r).is_identity().into();
            let t3 = c();
            // 4. Hash the signing root onto G2.
            let h = G2Affine::from(<G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                &msg,
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            ));
            let t4 = c();
            // 5. Miller loop over both pairs.
            let neg_g1 = G1Affine::from(-G1Projective::generator());
            let f = multi_miller_loop(&[(&neg_g1, &G2Prepared::from(s)), (&pk, &G2Prepared::from(h))]);
            let t5 = c();
            // 6. Final exponentiation.
            let ok = f.final_exponentiation() == Gt::identity();
            let t6 = c();
            assert!(sub_ok && ok, "signature did not verify");
            // 7. Helios's public Signature::verify on the same inputs, end to end.
            let hs: Signature = serde_json::from_str(&format!("\"0x{}\"", hex_lower(&sig))).unwrap();
            let t7 = c();
            assert!(hs.verify(&msg, &pk));
            let t8 = c();
            out.push(("nonsigners".into(), nonsigners.len() as u64));
            out.push(("aggregate_key".into(), t1 - t0));
            out.push(("sig_decompress".into(), t2 - t1));
            out.push(("helios_extra_subgroup_check".into(), t3 - t2));
            out.push(("hash_to_curve".into(), t4 - t3));
            out.push(("miller_loop".into(), t5 - t4));
            out.push(("final_exponentiation".into(), t6 - t5));
            out.push(("helios_signature_verify".into(), t8 - t7));
        }
        Input::Blst { agg, nonsigners, sig, msg } => blst_steps(&agg, &nonsigners, &sig, &msg, &mut out),
    }
    env::commit(&out);
}

/// FastAggregateVerify with blst, step by step. Keys are decompressed and
/// subgroup-checked like Helios does, so the comparison is like for like.
fn blst_steps(agg: &[u8], nonsigners: &[Vec<u8>], sig: &[u8], msg: &[u8], out: &mut Vec<(String, u64)>) {
    use blst::*;
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    unsafe {
        let key = |b: &[u8]| {
            let mut a = blst_p1_affine::default();
            assert!(blst_p1_uncompress(&mut a, b.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
            assert!(blst_p1_affine_in_g1(&a));
            a
        };
        // 1. Signers' key: aggregate minus non-signers.
        let t0 = c();
        let mut pk = blst_p1::default();
        blst_p1_from_affine(&mut pk, &key(agg));
        for n in nonsigners {
            let mut q = blst_p1::default();
            blst_p1_from_affine(&mut q, &key(n));
            blst_p1_cneg(&mut q, true);
            blst_p1_add_or_double(&mut pk, &pk, &q);
        }
        let mut pk_a = blst_p1_affine::default();
        blst_p1_to_affine(&mut pk_a, &pk);
        let t1 = c();
        // 2. Signature: decompress and subgroup check.
        let mut s = blst_p2_affine::default();
        assert!(blst_p2_uncompress(&mut s, sig.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p2_affine_in_g2(&s));
        let t2 = c();
        // 3. Hash the signing root onto G2.
        let mut h = blst_p2::default();
        blst_hash_to_g2(&mut h, msg.as_ptr(), msg.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0);
        let mut h_a = blst_p2_affine::default();
        blst_p2_to_affine(&mut h_a, &h);
        let t3 = c();
        // 4. Miller loops: e(pk, H(m)) * e(-G1, sig).
        let mut g = blst_p1::default();
        blst_p1_from_affine(&mut g, &*blst_p1_affine_generator());
        blst_p1_cneg(&mut g, true);
        let mut g_a = blst_p1_affine::default();
        blst_p1_to_affine(&mut g_a, &g);
        let (mut f1, mut f2, mut f) = (blst_fp12::default(), blst_fp12::default(), blst_fp12::default());
        blst_miller_loop(&mut f1, &h_a, &pk_a);
        blst_miller_loop(&mut f2, &s, &g_a);
        blst_fp12_mul(&mut f, &f1, &f2);
        let t4 = c();
        // 5. Final exponentiation.
        let mut r = blst_fp12::default();
        blst_final_exp(&mut r, &f);
        let ok = blst_fp12_is_one(&r);
        let t5 = c();
        assert!(ok, "blst: signature did not verify");
        out.push(("nonsigners".into(), nonsigners.len() as u64));
        out.push(("blst_aggregate_key".into(), t1 - t0));
        out.push(("blst_sig_decompress_and_subgroup".into(), t2 - t1));
        out.push(("blst_hash_to_curve".into(), t3 - t2));
        out.push(("blst_miller_loop".into(), t4 - t3));
        out.push(("blst_final_exponentiation".into(), t5 - t4));
        out.push(("blst_signature_total".into(), t5 - t0));
    }
}

/// SSZ hash_tree_root of a SyncCommittee: pubkeys as a 512-leaf Merkle tree of
/// 48-byte keys (each padded to 64 bytes), then hash(pubkeys_root, aggregate_root).
fn committee_root(keys: &[[u8; 48]], agg: &[u8; 48]) -> [u8; 32] {
    use sha2_010::{Digest, Sha256};
    let leaf = |k: &[u8; 48]| -> [u8; 32] {
        let mut b = [0u8; 64];
        b[..48].copy_from_slice(k);
        Sha256::digest(b).into()
    };
    let pair = |a: &[u8; 32], b: &[u8; 32]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    };
    let mut level: Vec<[u8; 32]> = keys.iter().map(leaf).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
    }
    pair(&level[0], &leaf(agg))
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
