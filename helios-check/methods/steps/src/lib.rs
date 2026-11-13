//! A committee update in three steps, as three LEZ transactions run it:
//! 1. every Helios rule except the signature, then the BLS preparation (signers'
//!    key, signature decode, hash to G2), leaving a job;
//! 2. the Miller loop of the job's pairing;
//! 3. the final exponentiation: the update is valid when the result is one.
//!
//! The guests in `src/bin` run one step each; `equivalence` runs them natively.
use alloy_primitives::B256;
use helios_consensus_core::{
    consensus_spec::ConsensusSpec,
    types::{Forks, GenericUpdate, LightClientStore, SyncCommittee},
    verify_generic_update_without_signature, SignatureInput,
};
use serde::{Deserialize, Serialize};
use ssz::Encode;

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

/// Why step 1 refused an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A Helios rule failed; Helios's error message.
    Rules(String),
    /// The supplied keys are not the ones the update needs, or a committee key
    /// does not decompress.
    Keys(String),
    /// The signature, or the signers' key, cannot make a valid signature.
    Signature(String),
}

/// SSZ root of a SyncCommittee straight over its key bytes (same root as tree_hash).
pub fn committee_root<S: ConsensusSpec>(c: &SyncCommittee<S>) -> B256 {
    use sha2_010::{Digest, Sha256};
    let n = c.pubkeys.len();
    assert!(n.is_power_of_two());
    let bytes = c.as_ssz_bytes(); // n x 48-byte keys, then the 48-byte aggregate
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
    let mut level: Vec<[u8; 32]> = bytes[..n * 48].chunks(48).map(leaf).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
    }
    B256::from(pair(&level[0], &leaf(&bytes[n * 48..])))
}

/// Step 1: Helios's rules, then the BLS preparation. Returns the job and the
/// cycles `cycles` counted for Helios's rules, the whole BLS preparation, and
/// the signers' key within it.
pub fn step1<S: ConsensusSpec>(
    update: &GenericUpdate<S>,
    expected_current_slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
    supplied_keys: Option<&[u8]>,
    cycles: &dyn Fn() -> u64,
) -> Result<(Job, [(&'static str, u64); 3]), Refusal> {
    let t0 = cycles();
    // Helios's rules (patched only to skip the signature and take our committee root).
    let si = verify_generic_update_without_signature::<S>(
        update,
        expected_current_slot,
        store,
        genesis_root,
        forks,
        committee_root::<S>,
    )
    .map_err(|e| Refusal::Rules(e.to_string()))?;
    let t1 = cycles();
    let (job, signers_key) = prepare(&si, supplied_keys, cycles)?;
    let t2 = cycles();
    Ok((job, [("helios_rules", t1 - t0), ("bls_prepare", t2 - t1), ("signers_key", signers_key)]))
}

/// The BLS preparation with blst. Returns the job and the cycles spent on the
/// signers' key.
fn prepare<S: ConsensusSpec>(
    si: &SignatureInput<S>,
    supplied: Option<&[u8]>,
    cycles: &dyn Fn() -> u64,
) -> Result<(Job, u64), Refusal> {
    use blst::*;
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let keys_err = |m: String| Refusal::Keys(m);
    let k0 = cycles();
    let size = si.bits.len();
    let committee = si.committee.as_ssz_bytes();
    // Member n's key as the committee commits to it; n = size is the aggregate key.
    let committed = |n: usize| &committee[n * 48..n * 48 + 48];
    if supplied.is_some_and(|keys| keys.len() % 96 != 0) {
        return Err(keys_err("supplied keys are 96 bytes each".into()));
    }
    let mut supplied = supplied.map(|keys| keys.chunks_exact(96));
    // Member n's key as a point. A supplied key only has to be on the curve and
    // compress to the committed key: compression is one-to-one on the curve, so
    // it is the committed point, and committee keys are in G1 (each passed
    // KeyValidate at deposit; the aggregate is their sum). Without supplied
    // keys, decompress and subgroup-check the committed key.
    let mut key = |n: usize| -> Result<blst_p1_affine, Refusal> {
        let mut a = blst_p1_affine::default();
        match supplied.as_mut() {
            Some(keys) => {
                let bytes = keys.next().ok_or_else(|| keys_err("fewer keys supplied than the update needs".into()))?;
                if unsafe { blst_p1_deserialize(&mut a, bytes.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
                    return Err(keys_err("supplied key is not on the curve".into()));
                }
                let mut compressed = [0u8; 48];
                unsafe { blst_p1_affine_compress(compressed.as_mut_ptr(), &a) };
                if compressed[..] != *committed(n) {
                    return Err(keys_err(format!("supplied key {n} is not the committee's")));
                }
            }
            None => {
                let ok = unsafe {
                    blst_p1_uncompress(&mut a, committed(n).as_ptr()) == BLST_ERROR::BLST_SUCCESS
                        && blst_p1_affine_in_g1(&a)
                };
                if !ok {
                    return Err(keys_err(format!("committee key {n} is not a point of G1")));
                }
            }
        }
        Ok(a)
    };
    // Signers' key: committee aggregate minus non-signers. Quorum (2/3) is
    // enforced when the update is applied, as in Helios.
    let mut pk = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut pk, &key(size)?) };
    for (n, signed) in si.bits.iter().enumerate() {
        if !signed {
            let q_a = key(n)?;
            unsafe {
                let mut q = blst_p1::default();
                blst_p1_from_affine(&mut q, &q_a);
                blst_p1_cneg(&mut q, true);
                blst_p1_add_or_double(&mut pk, &pk, &q);
            }
        }
    }
    if let Some(mut rest) = supplied {
        if rest.next().is_some() {
            return Err(keys_err("more keys supplied than the update needs".into()));
        }
    }
    let mut pk_a = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut pk_a, &pk) };
    if unsafe { blst_p1_affine_is_inf(&pk_a) } {
        return Err(Refusal::Signature("the signers' key is the identity".into()));
    }
    let signers_key = cycles() - k0;
    // Signature: decode and subgroup check.
    let mut s = blst_p2_affine::default();
    let sig_ok = unsafe {
        blst_p2_uncompress(&mut s, si.signature.as_ssz_bytes().as_ptr()) == BLST_ERROR::BLST_SUCCESS
            && blst_p2_affine_in_g2(&s)
    };
    if !sig_ok {
        return Err(Refusal::Signature("the signature is not a point of G2".into()));
    }
    // Hash the signing root onto G2.
    let mut h_a = blst_p2_affine::default();
    unsafe {
        let mut h = blst_p2::default();
        blst_hash_to_g2(&mut h, si.signing_root.as_ptr(), 32, DST.as_ptr(), DST.len(), core::ptr::null(), 0);
        blst_p2_to_affine(&mut h_a, &h);
    }

    let (mut pk_b, mut s_b, mut h_b) = ([0u8; 96], [0u8; 192], [0u8; 192]);
    unsafe {
        blst_p1_affine_serialize(pk_b.as_mut_ptr(), &pk_a);
        blst_p2_affine_serialize(s_b.as_mut_ptr(), &s);
        blst_p2_affine_serialize(h_b.as_mut_ptr(), &h_a);
    }
    Ok((Job { pk: pk_b.to_vec(), sig: s_b.to_vec(), hm: h_b.to_vec() }, signers_key))
}

/// Step 2: the Miller loop of e(pk, H(m)) * e(-G1, sig). Both pairs share one
/// loop (blst_miller_loop_n), which costs less than two loops and a
/// multiplication; the output is the same Fp12 element. Fails only on a job
/// step 1 did not write.
pub fn step2(job: &Job) -> Result<Miller, String> {
    use blst::*;
    let f = unsafe {
        let (mut pk, mut s, mut h) = (blst_p1_affine::default(), blst_p2_affine::default(), blst_p2_affine::default());
        let ok = job.pk.len() == 96
            && job.sig.len() == 192
            && job.hm.len() == 192
            && blst_p1_deserialize(&mut pk, job.pk.as_ptr()) == BLST_ERROR::BLST_SUCCESS
            && blst_p2_deserialize(&mut s, job.sig.as_ptr()) == BLST_ERROR::BLST_SUCCESS
            && blst_p2_deserialize(&mut h, job.hm.as_ptr()) == BLST_ERROR::BLST_SUCCESS;
        if !ok {
            return Err("not a job step 1 wrote".into());
        }
        let mut g = blst_p1::default();
        blst_p1_from_affine(&mut g, &*blst_p1_affine_generator());
        blst_p1_cneg(&mut g, true);
        let mut g_a = blst_p1_affine::default();
        blst_p1_to_affine(&mut g_a, &g);
        let qs: [*const blst_p2_affine; 2] = [&h, &s];
        let ps: [*const blst_p1_affine; 2] = [&pk, &g_a];
        let mut f = blst_fp12::default();
        blst_miller_loop_n(&mut f, qs.as_ptr(), ps.as_ptr(), 2);
        f
    };
    let bytes = unsafe { core::slice::from_raw_parts(&f as *const _ as *const u8, core::mem::size_of_val(&f)) }.to_vec();
    Ok(Miller { f: bytes })
}

/// Step 3: the final exponentiation; whether the signature is valid. Fails
/// only on an output step 2 did not write.
pub fn step3(miller: &Miller) -> Result<bool, String> {
    use blst::*;
    if miller.f.len() != core::mem::size_of::<blst_fp12>() {
        return Err("not a Miller loop output step 2 wrote".into());
    }
    Ok(unsafe {
        let mut f = blst_fp12::default();
        core::ptr::copy_nonoverlapping(miller.f.as_ptr(), &mut f as *mut _ as *mut u8, miller.f.len());
        let mut r = blst_fp12::default();
        blst_final_exp(&mut r, &f);
        blst_fp12_is_one(&r)
    })
}
