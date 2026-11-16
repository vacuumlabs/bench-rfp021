# Helios reuse check: cycle results (2026-11-12)

RISC Zero 3.0.5 executor (the zkVM version LEZ v0.4.0-rc3 uses), no proving: cycle
counts are deterministic. Counters wrap only the verification code; input parsing
is excluded. Helios `consensus-core` at a16z/helios `2922a47` (v0.12.0), unchanged.

Data: Helios's own mainnet fixtures (Capella, 2023, periods 862–867) and a fresh
mainnet bootstrap/update/finality update (Fulu, period 1908, fetched 2026-11-12 from
ethereum-beacon-api.publicnode.com). Both give the same numbers. Raw CSVs in `results/`.

## Helios as-is

| Case | Cycles |
|---|---|
| `verify_update`, committee handoff | 41.5M–43.5M (0–2 non-signers) |
| `verify_finality_update`, no handoff | 33.4M |

Breakdown (in-guest counters):

| Part | Helios (zkcrypto `bls12_381`, risc0 fork) | RISC Zero `blst` fork |
|---|---|---|
| Signers' key (aggregate minus non-signers) | 1.02M + 1.03M per non-signer | 0.45M + 0.455M per non-signer |
| Signature decompress + subgroup check | 1.46M + 8.04M (Helios checks the subgroup twice) | 0.53M |
| Hash to G2 | 2.81M | 1.18M |
| Miller loop | 8.90M | 4.16M |
| Final exponentiation | 10.83M | 3.65M |
| **Signature check total** | **32.0M** (+1.0M key) | **9.97M** (key included) |
| Next-committee SSZ root (handoff only) | 8.01M (generic `tree_hash`) | 1.25M direct over the key bytes, same root (asserted) |
| Everything else in Helios's rules | 0.37M (finality) / 0.43M (handoff) | same code |

## Helios rules + blst, split like Sextant (estimate from the counters above)

| Step | Contents | Cycles, handoff | Cycles, finality only |
|---|---|---|---|
| 1 | Helios rules, committee root, signers' key, signature decode, hash to G2 | 3.84M | 2.53M |
| 2 | Miller loop | 4.16M | 4.16M |
| 3 | Final exponentiation | 3.65M | 3.65M |
| **Total** | | **11.65M** | **10.34M** |

Each step is well under the 10M per-transaction cap. These are guest-function cycles
and exclude a LEZ program's own overhead (account reads/writes, instruction
decoding), so compare with Sextant's guest-level 11.2M / 12.6M, not its 13.4M gas.

## What this shows

- **Helios as-is does not work for us:** 33–43M cycles, about 3x Sextant. Almost all of it
  is the zkcrypto pairing library plus a redundant subgroup check, and the generic SSZ
  hashing of the next committee.
- **Helios's rules are cheap** (0.4M) and can be reused. The BLS step must use RISC Zero's
  `blst` fork, which is still a mature, RISC Zero-maintained library.
- **Reuse needs a small patch to Helios**, because `verify_generic_update` runs the signature
  check internally and the signature/committee-hash helpers are private: (1) expose the
  checks without the signature, (2) take a precomputed committee root. Both are small and
  could be offered upstream to a16z/helios.
- **Dependencies are fine:** `methods/compat` builds Helios, blst and LEZ v0.4.0-rc3 `lee_core`
  together into one RISC Zero guest (444 KB ELF), answering Sextant's dependency-tree concern.
- **Non-signers:** today's mainnet has 0–2 per update (last 10 periods), so cost is flat.
  Decompressing their keys, step 1 grows by 0.45M per non-signer, to 80.6M at the 2/3 floor
  (170 non-signers). With the keys supplied uncompressed (what Sextant and Affidavit do), it
  stays at 5.7M; see "Step 1 with many non-signers" below.


## The split, run for real (patched Helios + blst, mainnet Fulu data)

`methods/steps` runs the update as three programs, each feeding the next (step 1's job ->
step 2, the Miller output -> step 3); step 3 accepts the real mainnet signature. Helios is
patched with `../helios-patch/0001-split-signature-check.patch` (two hooks: run every rule
except the signature, and take a caller-computed committee root). Helios's own test suite
passes with the patch, and unpatched `verify_update` cycles are unchanged (within 11 cycles).

Work cycles (in-guest counters, harness input decoding excluded):

| Step | Handoff | Finality only |
|---|---|---|
| 1: Helios rules + committee root + signers' key, signature decode, hash to G2 | 4.34M (rules 1.91M, BLS prep 2.43M) | 2.78M (rules 0.35M, BLS prep 2.43M) |
| 2: Miller loop, both pairs in one loop | 3.27M | 3.27M |
| 3: Final exponentiation | 3.58M | 3.58M |
| **Total** | **11.19M** | **9.62M** |

Step 2 runs both pairs through one Miller loop (`blst_miller_loop_n`). Two loops and a
multiplication cost 4.10M; the output is the same, byte for byte.

Step 1's harness input decoding adds 5.9M (handoff) / 6.8M: risc0 serde spends one
32-bit word per byte of the 25 KB committees, and the header and update arrive as JSON.
A LEZ program reads the committee from account data instead, so this is not program cost.

## Step 1 with many non-signers

Today's mainnet updates have 0–2 non-signers. To see the floor, `helios-check nonsigners
fixtures/mainnet-now` re-signs both fixture updates with a generated 512-key committee,
which replaces the store's signing committee, with 0, 17 and 170 members not signing. 170 is
the most the 2/3 supermajority allows (342 × 3 ≥ 512 × 2). Helios accepts every re-signed
update natively, and all three steps run, with step 3 accepting the signature. Step 1 also
refuses wrong supplied keys: another member's key, a point off the curve, one key too few and
one too many. Raw: `results/desktop-ryzen-9800x3d/nonsigners.csv` (re-run 2026-11-16 at the current commit, same cycle counts).

Step 1 runs two ways:
- **Keys decompressed**, as before: the committee's aggregate key and each non-signer's key
  are decompressed and subgroup-checked.
- **Keys supplied**: whoever submits the update also supplies the aggregate key and the
  non-signers' keys uncompressed (`Step1In::supplied_keys`, 96 bytes each). Step 1 checks
  that each is on the curve and compresses to the committee's key: no square root, no
  subgroup check. Compression is one-to-one on the curve, so the point is the committed key,
  and committee keys are in G1 (each passed KeyValidate at deposit; the aggregate is their sum).

Step 1 work cycles (in-guest counters, harness input decoding excluded):

| Non-signers | Handoff, decompressed | Handoff, supplied | Finality only, decompressed | Finality only, supplied | Keys supplied |
|---|---|---|---|---|---|
| 0 | 4.34M | 3.91M | 2.78M | 2.34M | 96 B |
| 17 | 11.97M | 4.09M | 10.41M | 2.52M | 1.7 KB |
| 170 | 80.64M | **5.70M** | 79.07M | **4.13M** | 16.4 KB |

- A non-signer costs 0.449M decompressed and 0.011M supplied (the check plus the point
  subtraction both ways pay). Supplying the aggregate key saves another 0.44M on every update.
- At the floor the largest step is step 1 of a handoff update, 5.70M. Steps 2 and 3 don't
  change (3.27M and 3.58M), so a whole update is 12.5M across the three transactions.
- In both modes about 0.28M of the signers' key goes to copying the committee into bytes and
  walking the 512 participation bits.
- The supplied keys add 16.4 KB to step 1's input at the floor, about 1.9M more harness
  decoding through risc0 serde. The session total there is 13.5M; a LEZ program receives its
  input as borsh bytes instead.

`step-inputs` still runs step 1 without supplied keys, so its results and inputs are unchanged.

## Equivalence: unpatched Helios, patched Helios, the three steps

`equivalence/` runs every update natively four ways: unpatched Helios (a16z/helios at
`2922a47` as published, a git dependency), patched Helios, and the three steps (the
`helios_check_steps` code the guests run) once decompressing the signers' keys and once with
them supplied. Every verdict must equal unpatched Helios's, error message included, and the
stores must stay the same after each update. `cargo test -p equivalence -- --nocapture` lists
every case and its verdict.

| Cases | Count | Verdict, all four ways |
|---|---|---|
| Helios's own sync tests (its `testdata`, Capella to Gloas, minimal preset) | 17 tests, 57 updates, 7 forced updates | all accepted |
| consensus-specs v1.7.0-beta.2 sync tests (`scripts/fetch-spec-tests.sh`, then `CONSENSUS_SPEC_TESTS=… cargo test -p equivalence -- --include-ignored`) | 33 tests, 111 updates, 15 forced updates | all accepted |
| Mainnet: the period-1908 update and finality update from the bootstrap, and each update of periods 1900–1908 from the store the previous period's update leaves | 11 updates | all accepted |
| Tampered copies of those: a signature byte changed, the identity as the signature, a participation bit flipped, a finality branch node changed, a next committee branch node changed, another next committee | 64 | all rejected, for the same reason |
| The period-1908 update and finality update re-signed with 0, 17 and 170 non-signers, and at 170 with a participation bit flipped | 8 | 6 accepted, 2 rejected |

The sync tests contain only valid updates, so the rejections come from the tampered copies.
Step 1 also refuses wrong supplied keys: another member's key, a point off the curve, one
key too many, one too few, and a key cut short.

To have unpatched Helios alongside, the workspace depends on patched Helios by path
(`../helios-patched`) instead of patching the git source.

## Real proving (RISC0_DEV_MODE=0, CPU prover, AMD Ryzen 7 9800X3D, 8 cores / 16 threads, 15 GiB)

Each proof ran in its own process; peak memory is that process's maximum RSS. RISC Zero
crates pinned to LEZ v0.4.0-rc3's lock (risc0-zkvm 3.0.5, circuits 4.0.x). Raw: `results/proving.csv`.

| Program | Padded cycles (segments) | Proving | Peak memory |
|---|---|---|---|
| Deposit-log inclusion, typical receipt (428 B) | 0.52M (1) | **91 s** | 4.6 GiB |
| Step 3, final exponentiation | 4.19M (4) | 417 s | 9.2 GiB |
| Step 2, Miller loop (two loops; one shared loop is now 3.67M, 4 segments) | 4.72M (5) | 459 s | 9.2 GiB |
| Step 1, handoff, *incl. 5.9M harness decoding* | 11.53M (11) | 1,097 s | 9.2 GiB |
| Step 1, finality only, *incl. 6.8M harness decoding* | 10.49M (10) | 992 s | 9.2 GiB |
| Deposit-log inclusion, heavy receipt (47 KB, 300 logs) | 13.63M (13) | 1,325 s | 9.2 GiB |

Proving runs at about 97 s per 2^20-cycle segment, linearly. Without the harness decoding,
step 1 is about 5 segments: roughly **480 s** (derived, not measured). Peak memory is set by
the segment size (2^20), not by the program, so it stays at about 9.2 GiB. For reference,
Sextant reports 691 s / 544 s / 477 s for its three steps on an Apple M4 Pro CPU.

Receipt sizes in the CSV are composite receipts (about 280 KB per segment). A transaction
would carry a succinct receipt instead (about 225 KB per LEZ's cycle_bench); not measured here.

## Real proving on laptops

Same six inputs, same `prove_all.sh`, run by colleagues; cycle counts match the desktop's
(step 1 `input_decode` differs by a few hundred cycles, from the guest toolchain). Raw:
`results/macbook-air-m2-24gb/`, `results/laptop-thinkpad-t470-i7-7500u/`.

| Program | Desktop (9800X3D) | MacBook Air M2, 24 GB | ThinkPad T470, i7-7500U |
|---|---|---|---|
| Inclusion, typical receipt | 91 s | 116 s (7.3 GiB) | 898 s (4.6 GiB) |
| Step 3 | 417 s | 524 s (9.4 GiB) | 3,717 s (9.2 GiB) |
| Step 2 (two loops) | 459 s | 602 s (11.9 GiB) | |
| Step 1, handoff (incl. harness decoding) | 1,097 s | 1,479 s (9.4 GiB) | |
| Step 1, finality only (same) | 992 s | 1,337 s (9.4 GiB) | |
| Inclusion, 300-log receipt | 1,325 s | 1,797 s (9.4 GiB) | |

- **M2 Air** (4P + 4E cores, macOS 26.3.1, mains, CPU prover): all six, 98 min, 1.26–1.36x
  the desktop. Peak RSS up to 12.2 GiB on step 2 against 9.2 GiB on Linux; 16 GB is the
  practical minimum, 8 GB is not enough.
- **T470** (2017, 2 cores / 4 threads, Ubuntu 26.04, mains, desktop session in use): 2 of 6,
  about 929 s per 2^20 segment, about 9x the desktop. The rest would take about 11 h.

## Deposit-log inclusion (the RFP-022 user's step)

`methods/inclusion`: Merkle-Patricia proof of a receipt under a finalized block's
`receipts_root` (alloy-trie), EIP-2718 decode, then the deposit predicate (successful
transaction, token address, Transfer topic, amount >= minimum) and a statement id. Data:
USDC Transfer logs in mainnet block 26,398,402 (the block finalized by the 2026-11-12
finality update); the rebuilt receipts root matches the header's.

| Receipt | Proof nodes | Cycles, alloy default Keccak | Cycles, RISC Zero Keccak |
|---|---|---|---|
| tx 250, 1 log, 428 B | 5 | 595k | **69k** |
| tx 0, 7 logs, 1.6 KB | 3 | 634k | 77k |
| tx 194, 300 logs, 47 KB | 5 | 12.88M | 1.68M |

alloy-primitives 1.7 hashes with `sha3`/`keccak` 0.2.2 by default, which neither RISC Zero's
`tiny-keccak` patch nor LEZ's own `keccak` 0.2.0 patch reaches. Enabling alloy's `tiny-keccak`
feature routes it through RISC Zero's accelerated Keccak: about 9x cheaper, same statement ids.

## Still not measured

A LEZ 0.4 program shell around each step (account I/O, instruction decoding): estimated from
Sextant's numbers at about 0.8M across the three steps. Succinct receipt size. Storage-slot and account proofs (only receipt logs here).
