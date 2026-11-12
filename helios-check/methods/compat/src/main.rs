#![no_main]
use helios_consensus_core::{consensus_spec::MainnetConsensusSpec as S, types::LightClientStore};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    let raw: String = risc0_zkvm::guest::env::read();
    let store: LightClientStore<S> = serde_json::from_str(&raw).unwrap();
    let account = lee_core::account::Account::default();
    let bytes = borsh::to_vec(&account).unwrap();
    let mut p = blst::blst_p1_affine::default();
    let _ = unsafe { blst::blst_p1_uncompress(&mut p, bytes.as_ptr()) };
    risc0_zkvm::guest::env::commit(&(store.finalized_header.beacon().slot, bytes.len()));
}
