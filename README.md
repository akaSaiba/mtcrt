# MTC-RT proof of concept

A Go implementation of MTC-RT (revocation transparency for Merkle Tree
Certificates), built to benchmark the cost MTC-RT imposes on the CA, cosigners
and relying parties.

The following are not implemented: pruning of `crv_bits`/`A_n` and sync prefix
hashes, monitors, subject subscription, revocation-request authentication, RP
staleness policy and cosigner bootstrap / restart from a signing record.

## How to run

Requires Go 1.24+.

```sh
go test ./...
go run ./cmd/bench configs/bench.json
```

Progress is printed to stderr. The CSVs are written to the config's `out`
directory (`results/` for `configs/bench.json`), alongside a copy of
`config.json` and a `meta.json` file recording the run details (Go version,
OS/arch, CPU, cores, config path and start time).

All signatures use ML-DSA-44, implemented through Cloudflare's circl library.

## Folders

| Folder | What it is |
|---|---|
| `accum/` | A_n, the append-only Merkle tree of revocation events (RFC 9162). |
| `bench/` | Benchmark harness: loads a config, builds fixtures, runs each benchmark, writes CSVs and `meta.json`. |
| `bench/config/` | JSON config load, validation, and sweep expansion into cases. |
| `bench/fixture/` | Steady-state network fixture and revocation placement (uniform or clustered). |
| `bench/compress/` | Per-block Roaring encoding used for compressed size and lookup. |
| `bench/report/` | CSV writer and averaging of repeated timings. |
| `bench/benchmarks/` | Storage, rp-sync, disclosure, epoch, and lookup runners. |
| `ca/` | CA and distributor: epochs, cosignatures, full/incremental sync serving. |
| `cmd/bench/` | CLI entry point for `bench`. |
| `configs/` | JSON benchmark configs. |
| `cosigner/` | Proposal verification and durable signing. |
| `crv/` | `crv_bits` / `crv_tree`, with staged commit/rollback. |
| `epoch/` | One-process orchestration of CA, cosigners and RPs. Messages are passed as Go values; `wire.Marshal` is used mainly for byte accounting. |
| `merkle/` | Shared RFC 9162 Merkle code. |
| `policy/` | Cosigner policy used by relying parties: CA required, at least t valid signatures. |
| `results/` | Thesis CSV outputs, per-run config copy and machine details. |
| `rp/` | Sync verification, apply, and local lookup. |
| `sig/` | ML-DSA-44 keys, signing and verification. |
| `wire/` | Protocol messages, binary encoding, exact sizes. |

The `wire` package encodes structured fields into a fixed byte sequence, so
that message sizes, hashes and signatures are well defined. However, since
everything runs in one process, parties still exchange Go values directly. This
means that `wire.Marshal` is used mainly to accurately count sizes of structures in bytes.

To keep the harness fast, fixtures may be reused across reps. As revocations
accumulate across reps, the revoked fraction can drift above the target `r`.
When it drifts more than 5% above `r`, the fixture is rebuilt. Storage sizes are measured on
`crv_bits` alone, without building a full network.

## What each benchmark measures

Repeated timings and sizes are averaged over the measured reps (warmup reps are
excluded), and any column holding a mean is written as a whole number. All time
columns are in nanoseconds.

- **storage** (`storage.csv`): `raw_blocks`, `tree_leaf_hashes`, `roaring_per_block`, `list_32bit` (bytes).
- **rp-sync** (`rp_sync.csv`): full and incremental sync sizes (`blocks_sent`, `bytes_`*, `bytes_rn_listing`) and `t_apply_total_average` (ns).
- **disclosure** (`disclosure.csv`): authentication disclosure sizes (`bytes_auth`, `bytes_sigs`, `bytes_sig_framing`, `bytes_total`, `auth_share`).
- **epoch** (`epoch.csv`): mean `bytes_proposal` and epoch timings (`t_advance_average`, `t_serve_proposal_average`, `t_cosigner_average`, `t_add_cosig_average`, `t_publish_average`, `t_epoch_processing_average`, `t_ca_work_average`) in ns. Also includes a growth-only row with `k=0` (issues one block of certificates, no new revocations).
- **lookup** (`lookup.csv`): `t_raw_ns_per_lookup_average` and `t_roaring_per_block_ns_per_lookup_average` (ns/lookup).

## Where each time is measured

| Column | Benchmark | Package / function | Timed region |
|---|---|---|---|
| `t_advance_average` | epoch | `epoch.Network.RunEpoch` → `ca.CA.ProcessEpoch` | Queue handling, A_n append, `crv_bits` update, CA signature |
| `t_serve_proposal_average` | epoch | `epoch.Network.RunEpoch` → `ca.CA.ServeProposal` | Events + prefix hashes for one cosigner |
| `t_cosigner_average` | epoch | `epoch.Network.RunEpoch` → `cosigner.ReceiveProposal` | Verify, sign, durable record (serve time subtracted) |
| `t_add_cosig_average` | epoch | `ca.CA.AddCosignature` | Verify and store one cosignature |
| `t_publish_average` | epoch | `ca.CA.AddCosignature` → distributor publish | Publish once quorum is met |
| `t_epoch_processing_average` | epoch | derived in `bench/benchmarks` | CA + serve + one cosigner + add + publish |
| `t_ca_work_average` | epoch | derived in `bench/benchmarks` | CA + (t−1)×(serve+add) + publish |
| `t_apply_total_average` | rp-sync | `rp.RP.ApplySync` | Verify cosignatures, apply blocks, check `block_root` |
| `t_raw_ns_per_lookup_average` | lookup | `bench/benchmarks.RunLookup` | Batch of raw `Lookup` calls / count |
| `t_roaring_per_block_ns_per_lookup_average` | lookup | `bench/benchmarks.RunLookup` | Batch of per-block Roaring lookups / count |

## Simplifications

- Everything runs in one process, so there is no network latency.
- There is only one issuance log.
- At most one cosigner is real. Any remaining signatures come from shadow cosigners, which sign without verifying the proposal.
- The real cosigner still writes a signing record (with `fsync`) before releasing its signature, even though cosigners cannot restart from that record. Shadow cosigners do not write records.

## Glossary

| Spec | Go |
|---|---|
| `crv_bits` | `crv.Vector` |
| `crv_tree` | `merkle.Tree` field inside `crv.Vector` |
| `block_root` | `EpochState.BlockRoot` / `Vector.Root` |
| A_n | `accum.Log`, `AnRoot` for its root |
| revocation event | event index / `Events` |
| `signed_digest` | `SignedDigest` |
| `log_id`, `tree_size`, `minSerial`, `T_publish` | `LogID`, `TreeSize`, `MinSerial`, `TPublish` |
| epoch number `p` | `P` in structs, `p` for locals |
| B | `BlockSize` (bits) |
| proposal | `Proposal` |
| cosignature set | `[]Cosignature` |
| signing record | `SigningRecord` |
| shadow cosigner | `ShadowCosigner` |
| cold start | full sync (`SyncFull`) |
| incremental update | `SyncUpdate` |