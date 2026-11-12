//! Event-log inclusion: the step a bridge user proves when minting against a
//! deposit. `receipts_root` comes from an execution header the light client
//! already verified as finalized; here we only check the log is under it.
#![no_main]

use alloy_consensus::{ReceiptEnvelope, TxReceipt};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::{proof::verify_proof, Nibbles};
use risc0_zkvm::guest::env;
use serde::Deserialize;

risc0_zkvm::guest::entry!(main);

#[derive(Deserialize)]
struct Input {
    receipts_root: [u8; 32],
    tx_index: u64,
    receipt: Vec<u8>,
    proof: Vec<Vec<u8>>,
    log_index: u32,
    address: [u8; 20],
    topic0: [u8; 32],
    min_value: [u8; 32],
}

pub fn main() {
    let i: Input = env::read();
    let proof: Vec<Bytes> = i.proof.into_iter().map(Bytes::from).collect();
    let c = env::cycle_count;

    // 1. Merkle-Patricia proof: key is rlp(tx_index), value the EIP-2718 receipt.
    let t0 = c();
    let key = Nibbles::unpack(alloy_rlp::encode(i.tx_index));
    verify_proof(B256::from(i.receipts_root), key, Some(i.receipt.clone()), proof.iter()).expect("receipt not in receipts_root");
    let t1 = c();
    // 2. Decode the receipt.
    let r = ReceiptEnvelope::decode_2718(&mut i.receipt.as_slice()).expect("receipt decode");
    let t2 = c();
    // 3. Predicate: successful tx, log from the token, Transfer topic, amount >= min.
    assert!(r.status(), "transaction reverted");
    let log = &r.logs()[i.log_index as usize];
    assert_eq!(log.address.0 .0, i.address);
    assert_eq!(log.topics()[0].0, i.topic0);
    let amount: [u8; 32] = log.data.data[..32].try_into().unwrap();
    assert!(amount >= i.min_value, "amount below minimum");
    // Statement identifier over the attested fact (root, position, log contents).
    let mut id_in = Vec::with_capacity(32 + 12 + log.data.data.len() + 128);
    id_in.extend_from_slice(&i.receipts_root);
    id_in.extend_from_slice(&i.tx_index.to_be_bytes());
    id_in.extend_from_slice(&i.log_index.to_be_bytes());
    id_in.extend_from_slice(log.address.as_slice());
    for t in log.topics() {
        id_in.extend_from_slice(t.as_slice());
    }
    id_in.extend_from_slice(&log.data.data);
    let id = keccak256(&id_in);
    let t3 = c();

    let counters: Vec<(String, u64)> = vec![
        ("receipt_bytes".into(), i.receipt.len() as u64),
        ("proof_nodes".into(), proof.len() as u64),
        ("mpt_verify".into(), t1 - t0),
        ("receipt_decode".into(), t2 - t1),
        ("predicate_and_id".into(), t3 - t2),
        ("inclusion_total".into(), t3 - t0),
    ];
    env::commit(&(id.0, counters));
}
