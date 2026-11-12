//! `helios-check inclusion <fixture dir> <tx_index> <log_in_receipt>`:
//! builds a receipt-trie proof for one log of the finalized block and runs the
//! inclusion guest on it.
use std::fs;

use alloy::{eips::eip2718::Encodable2718, rpc::types::TransactionReceipt};
use alloy_primitives::{hex, B256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use helios_check_methods::INCLUSION_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
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

pub fn input(dir: &str, tx_index: usize, log_index: u32) -> (Vec<u8>, String) {
    let v: Value = serde_json::from_str(&fs::read_to_string(format!("{dir}/receipts.json")).unwrap()).unwrap();
    let receipts: Vec<TransactionReceipt> = serde_json::from_value(v["result"].clone()).unwrap();
    let encoded: Vec<Vec<u8>> = receipts.iter().map(|r| r.clone().into_primitives_receipt().inner.encoded_2718()).collect();
    let target_block = fs::read_to_string(format!("{dir}/target_block.txt")).unwrap();
    let expected_root: B256 = target_block.split_whitespace().nth(2).unwrap().parse().unwrap();

    // Receipt trie: key rlp(index), insert in key order.
    let target = Nibbles::unpack(alloy_rlp::encode(tx_index as u64));
    let mut items: Vec<(Nibbles, &Vec<u8>)> = encoded.iter().enumerate().map(|(i, e)| (Nibbles::unpack(alloy_rlp::encode(i as u64)), e)).collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![target.clone()]));
    for (k, e) in &items {
        hb.add_leaf(k.clone(), e);
    }
    let root = hb.root();
    assert_eq!(root, expected_root, "rebuilt receipts root does not match the finalized header");
    let proof: Vec<Vec<u8>> = hb.take_proof_nodes().matching_nodes_sorted(&target).into_iter().map(|(_, b)| b.to_vec()).collect();

    let log = &receipts[tx_index].inner.logs()[log_index as usize];
    let input = Input {
        receipts_root: root.0,
        tx_index: tx_index as u64,
        receipt: encoded[tx_index].clone(),
        proof,
        log_index,
        address: log.address().0 .0,
        topic0: log.topics()[0].0,
        min_value: [0u8; 32],
    };
    let label = format!("tx{tx_index}_log{log_index}_logs{}", receipts[tx_index].inner.logs().len());
    (risc0_zkvm::serde::to_vec(&input).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect(), label)
}

pub fn run(dir: &str, tx_index: usize, log_index: u32) -> Vec<String> {
    let (bytes, label) = input(dir, tx_index, log_index);
    let env = ExecutorEnv::builder().write_slice(&bytes).build().unwrap();
    let info = default_executor().execute(env, INCLUSION_ELF).expect("execute");
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    let (id, counters): ([u8; 32], Vec<(String, u64)>) = info.journal.decode().unwrap();
    println!("{label} id=0x{} session user={user} padded={padded} {counters:?}", hex::encode(id));
    let mut rows: Vec<String> = counters.iter().map(|(k, v)| format!("{label},{k},{v}")).collect();
    rows.push(format!("{label},session_user_cycles,{user}"));
    rows.push(format!("{label},session_padded_cycles,{padded}"));
    rows
}
