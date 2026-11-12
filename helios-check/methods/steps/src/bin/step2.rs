//! Step 2: the two Miller loops, e(pk, H(m)) * e(-G1, sig), from step 1's job.
#![no_main]
use helios_check_steps::{Job, Miller};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    use blst::*;
    let c = env::cycle_count;
    let t0 = c();
    let j: Job = env::read();
    let t1 = c();
    let f = unsafe {
        let (mut pk, mut s, mut h) = (blst_p1_affine::default(), blst_p2_affine::default(), blst_p2_affine::default());
        assert!(blst_p1_deserialize(&mut pk, j.pk.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p2_deserialize(&mut s, j.sig.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p2_deserialize(&mut h, j.hm.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        let mut g = blst_p1::default();
        blst_p1_from_affine(&mut g, &*blst_p1_affine_generator());
        blst_p1_cneg(&mut g, true);
        let mut g_a = blst_p1_affine::default();
        blst_p1_to_affine(&mut g_a, &g);
        let (mut f1, mut f2, mut f) = (blst_fp12::default(), blst_fp12::default(), blst_fp12::default());
        blst_miller_loop(&mut f1, &h, &pk);
        blst_miller_loop(&mut f2, &s, &g_a);
        blst_fp12_mul(&mut f, &f1, &f2);
        f
    };
    let t2 = c();
    let bytes = unsafe { core::slice::from_raw_parts(&f as *const _ as *const u8, core::mem::size_of_val(&f)) }.to_vec();
    env::commit(&(Miller { f: bytes }, vec![("input_decode", t1 - t0), ("miller_loop", t2 - t1)]));
}
