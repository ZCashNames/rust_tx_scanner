# rust_tx_scanner

A command-line scanner for **ZCash Ironwood shielded notes**. It connects to a
[lightwalletd](https://github.com/zcash/lightwalletd) gRPC endpoint, decrypts the notes a
viewing key can see, and prints them as JSON — value, memo, and position in chain order.

It is the ingest half of the [ZCash Name Service (zNS)](https://zcashnames.co): the
registrar's commands arrive as shielded notes, and this is what reads them. It is also
what makes the service **auditable by anyone** — the registrar publishes its protocol
address and viewing key, so a third party can point this tool at them and reconstruct the
entire command history independently.

Nothing about the tool is zNS-specific, though. It scans any Unified Address you hold a
viewing key for.

---

## What it does

* **Scans a block range** for notes decryptable by a viewing key, emitting one JSON object
  per matching block: height, hash, header timestamp, confirmations, and each note's value
  and decoded ZIP-302 memo.
* **Validates addresses** against the Orchard rule the zNS circuit enforces, so a command
  accepted at ingest is one the prover can also prove.
* **Reads single transactions**, blocks and chain tip, for diagnostics.

Note values and memos come from decryption, not from any index — so what it reports is what
the chain actually contains, independent of any server's bookkeeping.

## Building

```bash
cargo build --release
```

The binary lands at `target/release/rust_tx_scanner`.

## Usage

```
rust_tx_scanner [OPTIONS] <COMMAND>
```

| Option | Default | Notes |
|:---|:---|:---|
| `-g`, `--grpc` | `127.0.0.1:9067` | lightwalletd endpoint. A bare `host:port` gets `https://` unless it is local; an explicit scheme is honoured verbatim. |
| `-n`, `--network` | `mainnet` | `mainnet` or `testnet`. |
| `-k`, `--ivk` | — | Viewing key, `uview1…` (UFVK) or `uivk1…` (UIVK). Required by `scan`; optional for `gettx`, where it enables decryption. |

`--network` is deliberately strict — an unrecognised value is an error, never a silent
fall back to mainnet. The network selects the consensus branch id used to parse
transactions, and guessing wrong does not fail loudly: it makes every scan return nothing,
which is indistinguishable from "no payments arrived".

### Commands

| Command | Arguments | Purpose |
|:---|:---|:---|
| `scan` | `<START_BLOCK> <BLOCK_COUNT> [ALL]` | Scan a range for notes the key can decrypt. `ALL=1` also emits blocks with no matches. |
| `validateaddress` | `<ADDRESS>` | Prints `true`/`false` — is this a valid Orchard Unified Address on this network? |
| `gettx` | `<TX_HASH>` | Fetch one transaction; decrypts its notes when `--ivk` is given. |
| `blockhash` | `<BLOCK_ID>` | Block hash at a height. |
| `blockcount` | — | Current chain tip. |
| `syncstatus` | — | Endpoint sync state. |

### Examples

Scan 1,000 blocks from height 3429124:

```bash
rust_tx_scanner --grpc lightwalletd.example:443 --ivk uview1... scan 3429124 1000
```

Check an address the way the zNS circuit would:

```bash
rust_tx_scanner validateaddress u1...
```

## Viewing keys

A **UIVK** (`uivk1…`) reveals only notes *received*. A **UFVK** (`uview1…`) additionally
reveals notes *sent*. Scanning uses the incoming (`External`) scope in both cases, so it
never reports change or internal spends as income.

The key is passed on the command line rather than read from a file, which is a deliberate
choice for this tool's purpose: an *incoming* viewing key is published as part of the zNS
protocol — it is precisely what lets anyone run an independent indexer — so it is not a
secret, and its appearance in a process list discloses nothing that is not already public.

> [!IMPORTANT]
> That reasoning covers incoming keys. A **UFVK also exposes everything the wallet sent**,
> so treat one for a wallet you control as sensitive: prefer a UIVK when you only need to
> scan for incoming payments, and do not commit either to a repository.

## Auditing the zNS registrar

The registrar publishes its protocol address and viewing key in the
[zNS documentation](https://docs.zcashnames.co). With those you can replay the whole
command stream yourself:

```bash
rust_tx_scanner --ivk <published-key> scan <genesis-block> <count>
```

Every zNS command is a shielded note whose **value is the payment** and whose **ZIP-302
memo is the signed command**, so intent and payment are bound together in a single note
and cannot be separated. Feeding that stream through the open-source indexer reproduces
the state root, which can then be compared with the root anchored on-chain.

Before trusting a published pair, check that the key really controls the address:

```bash
cargo run --release --bin probe_ufvk -- <viewing-key> <address>
```

It prints `PAIRING OK` or `PAIRING FAIL`. This matters because a mismatched pair scans
clean — an auditor sees an empty result and cannot tell an honest "nothing here" from a
wrong key.

## Tests

```bash
cargo test
```

The suite covers ZIP-302 memo decoding (text, "no memo", reserved and binary forms,
embedded NULs, trailing padding), network parsing, block-height narrowing, endpoint URL
derivation, and the address-validation gate — including a cross-check of every case in the
prover's shared `ua_corpus.json`, so this tool's address rule cannot drift from the rule
the zNS circuit enforces. That check is skipped with a notice if the prover checkout is
not beside this one.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).
