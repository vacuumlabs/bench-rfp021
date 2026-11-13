//! Step 2: the Miller loop of e(pk, H(m)) * e(-G1, sig), from step 1's job
//! (`helios_check_steps::step2`).
#![no_main]
use helios_check_steps::Job;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let c = env::cycle_count;
    let t0 = c();
    let j: Job = env::read();
    let t1 = c();
    let miller = helios_check_steps::step2(&j).unwrap();
    let t2 = c();
    env::commit(&(miller, vec![("input_decode", t1 - t0), ("miller_loop", t2 - t1)]));
}
