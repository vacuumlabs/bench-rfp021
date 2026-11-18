# bench-rfp021

Cycle and real-proving measurements for our Logos RFP-021 bid (trustless Ethereum
state attestation on LEZ). An Ethereum light client, verifying **Ethereum mainnet**
sync-committee updates, runs inside the RISC Zero 3.0.5 zkVM, the version LEZ
v0.4.0-rc3 uses. No Logos/LEZ knowledge is needed to run anything here.

- `helios-check/`: the harness. `RESULTS.md` explains every number.
- `helios-patch/`: our two-hook patch to a16z/helios (run every light-client rule except
  the BLS signature; take a caller-computed committee root). `setup.sh` applies it.
- `helios-check/equivalence/`: unpatched Helios, patched Helios and the three steps must
  agree on every update (`cargo test -p equivalence -- --nocapture`; no zkVM).
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

## Results at a glance

All numbers are explained, with their raw CSVs and logs, in `helios-check/RESULTS.md`.

| What | Result |
|---|---|
| Helios as-is in the zkVM | 33–43M cycles per update |
| Our three steps (patched Helios + blst), mainnet Fulu data | step 1 3.91M (5.70M at 170 non-signers, 2.34M finality only), step 2 3.27M, step 3 3.58M |
| Equivalence: unpatched Helios, patched Helios, our steps | same verdict and error on 251 valid and tampered updates |
| Real proving, desktop (Ryzen 7 9800X3D, 8 cores) | about 100 s per 2^20-cycle segment, 9.2 GiB peak |
| Real proving, MacBook Air M2 (24 GB) | 1.26–1.36x the desktop |
| Real proving, ThinkPad T470 (2 cores) | about 9x the desktop (2 of 6 inputs) |
| Deposit-log inclusion | 69k cycles in a typical receipt, 1.68M in a 300-log one |

Still to be measured (see the end of `RESULTS.md`): a LEZ 0.4 program shell around each step,
succinct receipt size, and storage-slot and account proofs.

## Reproduce

```
cd helios-check
./target/release/helios-check step-inputs fixtures/mainnet-now results/inputs
./scripts/prove_all.sh          # real proving, about 1-2 hours on a desktop
cargo test -p equivalence -- --nocapture   # the equivalence test, no zkVM
```

`prove_all.sh` proves six inputs one at a time, each in its own process, and writes
`results/proving.csv` (time and peak memory per proof) and a log per proof in
`results/logs/`. Machine results are kept under `results/<machine>/`.
