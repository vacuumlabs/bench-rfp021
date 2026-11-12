//! Step 3: final exponentiation; the update is accepted if the result is one.
#![no_main]
use helios_check_steps::Miller;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    use blst::*;
    let c = env::cycle_count;
    let t0 = c();
    let m: Miller = env::read();
    let t1 = c();
    let ok = unsafe {
        let mut f = blst_fp12::default();
        assert_eq!(m.f.len(), core::mem::size_of::<blst_fp12>());
        core::ptr::copy_nonoverlapping(m.f.as_ptr(), &mut f as *mut _ as *mut u8, m.f.len());
        let mut r = blst_fp12::default();
        blst_final_exp(&mut r, &f);
        blst_fp12_is_one(&r)
    };
    let t2 = c();
    assert!(ok, "signature does not verify");
    env::commit(&(ok, vec![("input_decode", t1 - t0), ("final_exponentiation", t2 - t1)]));
}
