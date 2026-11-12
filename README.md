# bench-rfp021

Cycle and real-proving measurements for our Logos RFP-021 bid (trustless Ethereum
state attestation on LEZ). An Ethereum light client, verifying **Ethereum mainnet**
sync-committee updates, runs inside the RISC Zero 3.0.5 zkVM, the version LEZ
v0.4.0-rc3 uses. No Logos/LEZ knowledge is needed to run anything here.

- `helios-check/`: the harness. `RESULTS.md` explains every number.
- `helios-patch/`: our two-hook patch to a16z/helios (run every light-client rule except
  the BLS signature; take a caller-computed committee root). `setup.sh` applies it.
- `helios-check/results/desktop-ryzen-9800x3d/`: our reference results (AMD Ryzen 7 9800X3D,
  8 cores / 16 threads, 15 GiB, CPU proving).
- `helios-check/fixtures/mainnet-now/`: Ethereum mainnet light-client data and one block's
  receipts, fetched 2026-11-12.

## Setup (once)

1. Rust via rustup (https://rustup.rs). The toolchain in `helios-check/rust-toolchain.toml`
   installs itself on first build.
2. RISC Zero 3.0.5 exactly (other versions fail to verify proofs):
   ```
   curl -L https://risczero.com/install | bash
   rzup install cargo-risczero 3.0.5
   rzup install r0vm 3.0.5
   rzup show        # should list cargo-risczero 3.0.5 and r0vm 3.0.5
   ```
3. From this folder: `./setup.sh`, then
   ```
   cd helios-check
   cargo build --release -p helios-check     # first build takes several minutes
   ```

## Task 1 (main): run the benchmark on your laptop

RFP-021 asks for proving times on "a mid-range laptop and on the lowest specification
the team declares as supported". We only have desktop numbers.

```
cd helios-check
./target/release/helios-check step-inputs fixtures/mainnet-now results/inputs
./scripts/prove_all.sh          # real proving, about 1-2 hours; keep the laptop plugged in
```

`prove_all.sh` proves six inputs one at a time, each in its own process, and writes
`results/proving.csv` (time and peak memory per proof) and a log per proof in
`results/logs/`. The first line (deposit-log inclusion) takes about 1.5 minutes on our
desktop; if that works, the rest will.

**Done when:** copy `results/*.csv` into `results/<your-machine>/` (for example
`results/thinkpad-t14-32gb/`), add a `MACHINE.txt` there with CPU model, cores, RAM, OS,
and whether it ran on battery or mains, and commit that folder. If a step fails (for
example out of memory), commit the log from `results/logs/` instead; that is a result too.

## Task 2 (optional): equivalence test for the patch

Show the patched and unpatched Helios give the same verdict. Run `verify_update` /
`verify_finality_update` from both on Helios's own spec vectors
(`helios-patched/ethereum/consensus-core/testdata/`) and on our fixtures, plus tampered
copies: a changed signature byte, a flipped participation bit, a wrong proof branch node,
a swapped next committee. Assert identical accept/reject for every case. Plain Rust, no zkVM.
Put it in a new crate `helios-check/equivalence/`.

**Done when:** `cargo test -p equivalence` passes and lists the cases.

## Task 3 (optional): step 1 with many non-signers

Today's Ethereum mainnet has 0-2 non-signers per update, so step 1 costs about 4.4M cycles.
At the 2/3 participation floor (170 non-signers) each non-signer adds about 0.455M, so step 1
would not fit LEZ's 10M-cycle transaction limit. Fix: the submitter supplies each non-signer's
key uncompressed, and the guest only checks it is on the curve and compresses to the committed
48 bytes (no square root, no subgroup check). Add this to `methods/steps/src/bin/step1.rs` and
measure step 1 at 0, 17 and 170 synthetic non-signers (clear bits in a copy of the update; the
signature will then fail in step 3, which is fine for counting step 1 cycles).

**Done when:** a small table of step 1 cycles vs non-signers, added to `RESULTS.md`.
