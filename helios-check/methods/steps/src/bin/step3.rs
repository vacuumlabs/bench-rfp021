//! Step 3: final exponentiation; the update is accepted if the result is one
//! (`helios_check_steps::step3`).
#![no_main]
use helios_check_steps::Miller;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let c = env::cycle_count;
    let t0 = c();
    let m: Miller = env::read();
    let t1 = c();
    let ok = helios_check_steps::step3(&m).unwrap();
    let t2 = c();
    assert!(ok, "signature does not verify");
    env::commit(&(ok, vec![("input_decode", t1 - t0), ("final_exponentiation", t2 - t1)]));
}
