//! Step 1: every Helios rule except the signature, then the BLS preparation
//! (signers' key, signature decode, hash to G2) with blst. The keys for the
//! signers' key can be supplied uncompressed (`Step1In::supplied_keys`), so a
//! non-signer costs a curve check instead of a decompression. The step itself
//! is `helios_check_steps::step1`; this guest decodes its input and counts.
#![no_main]
use alloy_primitives::B256;
use helios_check_steps::Step1In;
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as S,
    types::{FinalityUpdate, Forks, GenericUpdate, LightClientHeader, LightClientStore, SyncCommittee, Update},
};
use risc0_zkvm::guest::env;
use ssz::Decode;

risc0_zkvm::guest::entry!(main);

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

    let cycles = || env::cycle_count();
    let (job, counters) = helios_check_steps::step1(
        &update,
        i.expected_current_slot,
        &store,
        B256::from(i.genesis_root),
        &forks,
        i.supplied_keys.as_deref(),
        &cycles,
    )
    .unwrap_or_else(|refusal| panic!("step 1 refused the update: {refusal:?}"));
    let mut out = vec![("input_decode", t1 - t0)];
    out.extend(counters);
    env::commit(&(job, out));
}
