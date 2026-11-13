//! Step 1: every Helios rule except the signature, then the BLS preparation
//! (signers' key, signature decode, hash to G2) with blst. The keys for the
//! signers' key can be supplied uncompressed (`Step1In::supplied_keys`), so a
//! non-signer costs a curve check instead of a decompression.
#![no_main]
use alloy_primitives::B256;
use helios_check_steps::{Job, Step1In};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as S,
    types::{FinalityUpdate, Forks, GenericUpdate, LightClientHeader, LightClientStore, SyncCommittee, Update},
    verify_generic_update_without_signature,
};
use risc0_zkvm::guest::env;
use ssz::{Decode, Encode};

risc0_zkvm::guest::entry!(main);

/// SSZ root of a SyncCommittee straight over its key bytes (same root as tree_hash).
fn committee_root(c: &SyncCommittee<S>) -> B256 {
    use sha2_010::{Digest, Sha256};
    let bytes = c.as_ssz_bytes(); // 512 x 48-byte keys, then the 48-byte aggregate
    let leaf = |k: &[u8]| -> [u8; 32] {
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
    let mut level: Vec<[u8; 32]> = bytes[..512 * 48].chunks(48).map(leaf).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
    }
    B256::from(pair(&level[0], &leaf(&bytes[512 * 48..])))
}

pub fn main() {
    let c = env::cycle_count;
    let t0 = c();
    let i: Step1In = env::read();
    let header: LightClientHeader = serde_json::from_str(&i.finalized_header_json).unwrap();
    let store = LightClientStore::<S> {
        finalized_header: header.clone(),
        current_sync_committee: SyncCommittee::from_ssz_bytes(&i.current_committee_ssz).unwrap(),
        next_sync_committee: i.next_committee_ssz.as_ref().map(|b| SyncCommittee::from_ssz_bytes(b).unwrap()),
        optimistic_header: header,
        ..Default::default()
    };
    let update: GenericUpdate<S> = if i.is_finality_update {
        GenericUpdate::from(&serde_json::from_str::<FinalityUpdate<S>>(&i.update_json).unwrap())
    } else {
        GenericUpdate::from(&serde_json::from_str::<Update<S>>(&i.update_json).unwrap())
    };
    let forks: Forks = serde_json::from_str(&i.forks_json).unwrap();
    let t1 = c();

    // Helios's rules (patched only to skip the signature and take our committee root).
    let si = verify_generic_update_without_signature::<S>(&update, i.expected_current_slot, &store, B256::from(i.genesis_root), &forks, committee_root)
        .expect("Helios rejected the update");
    let t2 = c();

    // BLS preparation with blst.
    let (job, signers_key) = unsafe { prepare(&si, i.supplied_keys.as_deref()) };
    let t3 = c();
    env::commit(&(
        job,
        vec![("input_decode", t1 - t0), ("helios_rules", t2 - t1), ("bls_prepare", t3 - t2), ("signers_key", signers_key)],
    ));
}

/// Returns the job and the cycles spent on the signers' key (part of the BLS
/// preparation).
unsafe fn prepare(si: &helios_consensus_core::SignatureInput<S>, supplied: Option<&[u8]>) -> (Job, u64) {
    use blst::*;
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let k0 = env::cycle_count();
    let committee = si.committee.as_ssz_bytes();
    // Member n's key as the committee commits to it; n = 512 is the aggregate key.
    let committed = |n: usize| &committee[n * 48..n * 48 + 48];
    let mut supplied = supplied.map(|keys| {
        assert!(keys.len() % 96 == 0, "supplied keys are 96 bytes each");
        keys.chunks_exact(96)
    });
    // Member n's key as a point. A supplied key only has to be on the curve and
    // compress to the committed key: compression is one-to-one on the curve, so
    // it is the committed point, and committee keys are in G1 (each passed
    // KeyValidate at deposit; the aggregate is their sum). Without supplied
    // keys, decompress and subgroup-check the committed key.
    let mut key = |n: usize| {
        let mut a = blst_p1_affine::default();
        match supplied.as_mut() {
            Some(keys) => {
                let bytes = keys.next().expect("fewer keys supplied than the update needs");
                assert!(blst_p1_deserialize(&mut a, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS, "supplied key is not on the curve");
                let mut compressed = [0u8; 48];
                blst_p1_affine_compress(compressed.as_mut_ptr(), &a);
                assert!(compressed[..] == *committed(n), "supplied key {n} is not the committee's");
            }
            None => {
                assert!(blst_p1_uncompress(&mut a, committed(n).as_ptr()) == BLST_ERROR::BLST_SUCCESS);
                assert!(blst_p1_affine_in_g1(&a));
            }
        }
        a
    };
    // Signers' key: committee aggregate minus non-signers. Quorum (2/3) is
    // enforced when the update is applied, as in Helios.
    let mut pk = blst_p1::default();
    blst_p1_from_affine(&mut pk, &key(512));
    for (n, signed) in si.bits.iter().enumerate() {
        if !signed {
            let mut q = blst_p1::default();
            blst_p1_from_affine(&mut q, &key(n));
            blst_p1_cneg(&mut q, true);
            blst_p1_add_or_double(&mut pk, &pk, &q);
        }
    }
    if let Some(mut rest) = supplied {
        assert!(rest.next().is_none(), "more keys supplied than the update needs");
    }
    let mut pk_a = blst_p1_affine::default();
    blst_p1_to_affine(&mut pk_a, &pk);
    assert!(!blst_p1_affine_is_inf(&pk_a));
    let signers_key = env::cycle_count() - k0;
    // Signature: decode and subgroup check.
    let mut s = blst_p2_affine::default();
    assert!(blst_p2_uncompress(&mut s, si.signature.as_ssz_bytes().as_ptr()) == BLST_ERROR::BLST_SUCCESS);
    assert!(blst_p2_affine_in_g2(&s));
    // Hash the signing root onto G2.
    let mut h = blst_p2::default();
    blst_hash_to_g2(&mut h, si.signing_root.as_ptr(), 32, DST.as_ptr(), DST.len(), core::ptr::null(), 0);
    let mut h_a = blst_p2_affine::default();
    blst_p2_to_affine(&mut h_a, &h);

    let (mut pk_b, mut s_b, mut h_b) = ([0u8; 96], [0u8; 192], [0u8; 192]);
    blst_p1_affine_serialize(pk_b.as_mut_ptr(), &pk_a);
    blst_p2_affine_serialize(s_b.as_mut_ptr(), &s);
    blst_p2_affine_serialize(h_b.as_mut_ptr(), &h_a);
    (Job { pk: pk_b.to_vec(), sig: s_b.to_vec(), hm: h_b.to_vec() }, signers_key)
}
