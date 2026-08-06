use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;

use lightwallet_protocol::{
    CompactTxStreamerClient, ChainSpec, BlockId, TxFilter, Empty,
};
use tonic::codec::CompressionEncoding;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use zcash_address::unified::{Address, Ufvk, Uivk, Receiver, Fvk, Ivk, Container, Encoding};
use orchard::keys::{PreparedIncomingViewingKey, Scope, FullViewingKey, IncomingViewingKey};
use orchard::note_encryption::IronwoodDomain;
use zcash_protocol::consensus::{BranchId, BlockHeight, Network, Parameters};
use zcash_primitives::transaction::Transaction;
use zcash_note_encryption::try_note_decryption;

/// Maximum concurrent `GetBlock` calls issued while scanning a range.
const BLOCK_FETCH_CONCURRENCY: usize = 24;

/// Maximum concurrent `GetTransaction` calls issued while scanning a range.
const TX_FETCH_CONCURRENCY: usize = 32;

/// Result entry for matched notes during scanning.
#[derive(Clone)]
struct ScanNote {
    amount: u64,
    memo: String,
}

/// Result entry for matched transactions during scanning.
#[derive(Clone)]
struct ScanTx {
    tx_id: String,
    tx_block_index: u64,
    notes: std::collections::BTreeMap<u64, ScanNote>, // input_index -> ScanNote
}

/// Result entry for matched blocks during scanning.
struct ScanBlock {
    block_id: u64,
    block_hash: Vec<u8>,
    /// Header timestamp (unix seconds). Emitted so consumers can bound a command's
    /// nonce against consensus data rather than their own wall clock — every indexer
    /// replaying this block sees the identical value, whenever it replays.
    block_time: u32,
    confirmations: u64,
    txs: Vec<ScanTx>,
}

/// Maps the `--network` argument onto a consensus network.
///
/// Deliberately strict: an unrecognised value is an error rather than a silent fall back
/// to mainnet, because the network selects the consensus branch id used to parse
/// transactions. Guessing wrong does not fail loudly — it makes every scan return
/// nothing, which looks identical to "no payments arrived".
fn parse_network(name: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match name.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::MainNetwork),
        "testnet" | "test" => Ok(Network::TestNetwork),
        other => Err(format!(
            "Unknown network '{other}'. Expected 'mainnet' or 'testnet'."
        )
        .into()),
    }
}

/// Narrows a block height to the `u32` a `BlockHeight` holds, erroring rather than
/// truncating. Also catches the `u64::MAX` sentinel lightwalletd uses for a transaction
/// that is not in a block.
fn to_block_height(height: u64) -> Result<BlockHeight, Box<dyn std::error::Error>> {
    u32::try_from(height)
        .map(BlockHeight::from_u32)
        .map_err(|_| format!("Block height {height} does not fit in u32").into())
}

/// Returns the raw 43-byte Orchard (0x03) receiver payload from a unified-address item, if present.
fn orchard_receiver_bytes(item: &Receiver) -> Option<[u8; 43]> {
    if let Receiver::Orchard(data) = item {
        Some(*data)
    } else {
        None
    }
}

/// Parses the Orchard (0x03) receiver of a unified address into an `orchard::Address`.
///
/// Ironwood defines no receiver of its own: ZIP 229 states that adding the Ironwood pool
/// "does not change address structures or encodings", and that Orchard key material grants
/// authority over notes in both pools. ZIP 316 leaves 0x04 unassigned, so gating on it
/// would reject every address a real wallet produces.
fn orchard_address_from_ua(ua: &Address) -> Option<orchard::Address> {
    let raw = ua.items().iter().find_map(orchard_receiver_bytes)?;
    Option::from(orchard::Address::from_raw_address_bytes(&raw))
}

/// The ingest gate: whether `address` is a target address this deployment will accept.
///
/// This is the whole of the `validateaddress` subcommand, extracted so it can be tested.
/// `Rpc::validateAddress` in the PHP registrar shells out to exactly this, so every
/// target address in every command passes through here before it can reach a batch.
///
/// It must never accept an address the circuit would reject. `zns-core`'s
/// `is_address_valid` requires a Unified Address, on the matching network, carrying an
/// Orchard receiver; this additionally decodes that receiver as a curve point, because
/// `orchard::Address::from_raw_address_bytes` is available here and is not affordable
/// inside the zkVM (SP1 has no Pallas precompile). Being *stricter* is the safe
/// direction: it can only reject a command early, never admit one that turns out to be
/// unprovable and wedges the batch that carries it.
fn address_is_valid(address: &str, network: Network) -> bool {
    match Address::decode(address) {
        Ok((net, ua)) => net == network.network_type() && orchard_address_from_ua(&ua).is_some(),
        Err(_) => false,
    }
}

/// Validate the viewing key contains an Orchard (0x03) component for the configured network and
/// prepare the incoming IVK (Scope::External — incoming notes only, never change/internal spends).
fn prepare_orchard_ivk(
    ivk_str: &str,
    network: Network,
) -> Result<PreparedIncomingViewingKey, Box<dyn std::error::Error>> {
    let mut key_payload: Option<Vec<u8>> = None;

    let key_net = if ivk_str.starts_with("uview") {
        let (net, ufvk) = Ufvk::decode(ivk_str)
            .map_err(|e| format!("Failed to decode UFVK: {e:?}"))?;
        for fvk in ufvk.items() {
            if let Fvk::Orchard(data) = fvk {
                key_payload = Some(data.to_vec());
                break;
            }
        }
        net
    } else if ivk_str.starts_with("uivk") {
        let (net, uivk) = Uivk::decode(ivk_str)
            .map_err(|e| format!("Failed to decode UIVK: {e:?}"))?;
        for ivk in uivk.items() {
            if let Ivk::Orchard(data) = ivk {
                key_payload = Some(data.to_vec());
                break;
            }
        }
        net
    } else {
        return Err("Invalid viewing key format. Must start with uview1... or uivk1...".into());
    };

    if key_net != network.network_type() {
        return Err(format!(
            "Viewing key is for network {key_net:?} but scanner is running with --network {:?}",
            network.network_type()
        )
        .into());
    }

    let payload = key_payload.ok_or("Viewing key must contain an Orchard (0x03) key component")?;

    if payload.len() == 96 {
        let fvk_bytes: [u8; 96] = payload.as_slice().try_into()
            .map_err(|_| "Invalid FVK payload size")?;
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or("Failed to parse FullViewingKey from bytes")?;
        let external_ivk = fvk.to_ivk(Scope::External);
        Ok(PreparedIncomingViewingKey::new(&external_ivk))
    } else if payload.len() == 64 {
        let ivk_bytes: [u8; 64] = payload.as_slice().try_into()
            .map_err(|_| "Invalid IVK payload size")?;
        let ivk: Option<IncomingViewingKey> = IncomingViewingKey::from_bytes(&ivk_bytes).into();
        let ivk = ivk.ok_or("Failed to parse IncomingViewingKey from bytes")?;
        Ok(PreparedIncomingViewingKey::new(&ivk))
    } else {
        Err(format!("Unexpected viewing key payload length: {}", payload.len()).into())
    }
}

#[derive(Parser)]
#[command(name = "rust_tx_scanner", version, about = "ZCash Ironwood Transactions Scanner")]
struct Cli {
    #[arg(short, long, global = true, default_value = "127.0.0.1:9067")]
    grpc: String,

    #[arg(short, long, global = true, default_value = "mainnet")]
    network: String,

    /// Ironwood viewing key ("uview1…" UFVK or "uivk1…" UIVK). Required by `scan`;
    /// optional for `gettx`, where it enables note decryption.
    ///
    /// Passed on the command line rather than read from a file because an *incoming*
    /// viewing key is published as part of the protocol — it is what lets anyone run an
    /// independent indexer — so it is not a secret and its appearance in the process list
    /// discloses nothing.
    #[arg(short = 'k', long = "ivk", global = true)]
    ivk: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Checks whether an address is a valid Orchard (0x03) Unified Address for the configured network.
    Validateaddress {
        address: String,
    },
    /// Scans a block range for Ironwood notes decryptable by `--ivk`.
    ///
    /// Emits one JSON object per matching block: height, hash, header timestamp,
    /// confirmations, and every matching note with its value and decoded memo.
    Scan {
        start_block: u64,
        block_count: u64,
        /// Set to 1 to include blocks with no matching transactions in the output.
        all: Option<u8>,
    },
    Blockhash {
        block_id: u64,
    },
    Gettx {
        tx_hash: String,
    },
    Blockcount,
    Syncstatus,
}

/// Helper: reverse bytes and hex-encode (ZCash display convention for hashes).
#[inline]
fn reverse_hex(bytes: &[u8]) -> String {
    let mut reversed = bytes.to_vec();
    reversed.reverse();
    const_hex::encode(reversed)
}

/// Decodes a ZIP-302 memo field into its text representation.
///
/// Per ZIP-302 the 512-byte memo is interpreted by its first byte:
/// * `0x00..=0xF4` — a UTF-8 text memo, zero-padded on the right.
/// * `0xF5` — reserved; treated as "not text" here.
/// * `0xF6` followed by all zero bytes — explicitly "no memo".
/// * `0xF7..=0xFF` — reserved for future non-text formats.
///
/// Only trailing padding is stripped (rather than truncating at the first zero byte), so a text
/// memo carrying an embedded NUL keeps everything after it instead of being silently cut short.
///
/// Non-text memos yield an empty string; see `memo_is_text` for distinguishing "no memo" from a
/// reserved/binary payload that this function cannot represent.
fn decode_memo(memo: &[u8; 512]) -> String {
    if !memo_is_text(memo) {
        return String::new();
    }
    let end = memo.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8_lossy(&memo[..end]).into_owned()
}

/// Returns true when a ZIP-302 memo holds a UTF-8 text payload (first byte `0x00..=0xF4`).
#[inline]
fn memo_is_text(memo: &[u8; 512]) -> bool {
    memo[0] <= 0xF4
}

/// Build candidate URLs from the user-provided gRPC address.
fn build_urls(grpc: &str) -> Vec<String> {
    if grpc.starts_with("http://") || grpc.starts_with("https://") {
        // An explicit scheme is honoured as given. This is the escape hatch for anyone
        // who genuinely needs plaintext to a remote node: they have to ask for it.
        return vec![grpc.to_string()];
    }

    if is_loopback_host(grpc) {
        // Loopback needs no transport security, and a local lightwalletd usually has no
        // certificate, so plaintext is tried first.
        vec![format!("http://{grpc}"), format!("https://{grpc}")]
    } else {
        // HTTPS ONLY for remote hosts — deliberately no plaintext fallback.
        //
        // Falling back would mean that anyone able to disturb the TLS handshake (an
        // expired certificate, a captive portal, or simply dropping port-443 packets)
        // silently downgrades the connection and then controls every block, transaction
        // and memo this scanner reports. Commands are signed, so an attacker could not
        // forge one — but they could omit them, reorder them, or present a fabricated
        // chain, and the reorg check would confirm it against the same compromised node.
        //
        // The registrar batches from this data and independent indexers audit with it,
        // so a silent downgrade undermines both roles at once.
        vec![format!("https://{grpc}")]
    }
}

/// Whether `grpc` refers to the local machine, where plaintext gRPC is acceptable.
fn is_loopback_host(grpc: &str) -> bool {
    let host = grpc.rsplit_once(':').map_or(grpc, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1"
}

/// Attempt to connect and probe each candidate URL, returning the first working client.
async fn connect_client(urls: Vec<String>) -> Result<CompactTxStreamerClient<Channel>, String> {
    let mut errors = Vec::new();
    for url in urls {
        let endpoint_result = if url.starts_with("https://") {
            let tls = ClientTlsConfig::new().with_native_roots();
            Endpoint::from_shared(url.clone()).and_then(|ep| ep.tls_config(tls))
        } else {
            Endpoint::from_shared(url.clone())
        };

        let endpoint = match endpoint_result {
            // Bound the connection attempt so a firewalled/hung endpoint fails fast instead of
            // hanging the CLI forever with no exit code for the caller to react to.
            Ok(ep) => ep.connect_timeout(Duration::from_secs(10)),
            Err(e) => {
                errors.push(format!("{url}: endpoint error: {e}"));
                continue;
            }
        };

        match endpoint.connect().await {
            Ok(channel) => {
                // Ask the server to gzip responses — worthwhile now that `scan` fetches every
                // full transaction in a block range rather than a compact summary.
                let mut client = CompactTxStreamerClient::new(channel)
                    .accept_compressed(CompressionEncoding::Gzip);
                match client.get_latest_block(ChainSpec::default()).await {
                    Ok(_) => return Ok(client),
                    Err(e) => errors.push(format!("{url}: probe error: {e}")),
                }
            }
            Err(e) => errors.push(format!("{url}: connect error: {e}")),
        }
    }
    Err(format!("Failed to connect to gRPC server.\nDetails:\n{}", errors.join("\n")))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let network = parse_network(&args.network)?;

    if let Commands::Validateaddress { ref address } = args.command {
        println!("{}", address_is_valid(address, network));
        return Ok(());
    }

    let urls = build_urls(&args.grpc);
    let mut client = connect_client(urls).await?;

    match args.command {
        Commands::Validateaddress { .. } => unreachable!(),
        Commands::Blockcount => {
            let block = client.get_latest_block(ChainSpec::default()).await?.into_inner();
            println!("{}", block.height);
        }

        Commands::Syncstatus => {
            let info = client.get_lightd_info(Empty {}).await?.into_inner();
            let is_synced = (info.block_height.saturating_add(5) >= info.estimated_height) && info.block_height > 0;
            let result = serde_json::json!({
                "block_height": info.block_height,
                "estimated_height": info.estimated_height,
                "is_synced": is_synced,
            });
            println!("{}", serde_json::to_string(&result)?);
        }

        Commands::Blockhash { block_id } => {
            let block = client.get_block(BlockId { height: block_id, hash: vec![] }).await?.into_inner();
            println!("{}", reverse_hex(&block.hash));
        }

        Commands::Gettx { tx_hash } => {
            let latest_height = client.get_latest_block(ChainSpec::default()).await?.into_inner().height;

            let mut txid_bytes = const_hex::decode(&tx_hash)
                .map_err(|e| format!("Invalid hex transaction hash: {e}"))?;
            txid_bytes.reverse();

            let raw_tx = client.get_transaction(TxFilter { hash: txid_bytes, ..Default::default() }).await
                .map_err(|e| format!("Transaction not found: {e}"))?
                .into_inner();

            let is_orphaned = raw_tx.height == u64::MAX;
            let confirmations = if raw_tx.height > 0 && raw_tx.height < u64::MAX && latest_height >= raw_tx.height {
                latest_height - raw_tx.height + 1
            } else {
                0
            };

            let block_hash = if raw_tx.height > 0 && raw_tx.height < u64::MAX {
                match client.get_block(BlockId { height: raw_tx.height, hash: vec![] }).await {
                    Ok(b) => reverse_hex(&b.into_inner().hash),
                    Err(_) => String::new(),
                }
            } else {
                String::new()
            };

            let mut amount = 0u64;

            if !is_orphaned {
                if let Some(ivk) = &args.ivk {
                    if !raw_tx.data.is_empty() {
                        let prepared_ivk = prepare_orchard_ivk(ivk, network)?;

                        let tx_height = if raw_tx.height > 0 && raw_tx.height < u64::MAX {
                            to_block_height(raw_tx.height)?
                        } else {
                            to_block_height(latest_height)?
                        };
                        let branch_id = BranchId::for_height(&network, tx_height);

                        let tx = Transaction::read(&mut &raw_tx.data[..], branch_id)
                            .map_err(|e| format!("Failed to parse raw transaction: {e}"))?;

                        if let Some(bundle) = tx.ironwood_bundle() {
                            for action in bundle.actions() {
                                let domain = IronwoodDomain::for_action(action);
                                // Every note this viewing key can decrypt counts, whichever
                                // diversified address it was sent to. See the note on the
                                // scan loop for why this is not filtered by address.
                                if let Some((note, _recipient, _memo)) = try_note_decryption(&domain, &prepared_ivk, action) {
                                    amount += note.value().inner();
                                }
                            }
                        }
                    }
                }
            }

            let result = serde_json::json!({
                "block_hash": block_hash,
                "confirmations": confirmations,
                "amount": amount,
                "is_orphaned": is_orphaned
            });
            println!("{}", serde_json::to_string(&result)?);
        }

        Commands::Scan { start_block, block_count, all } => {
            let ivk = args.ivk.as_ref().ok_or(
                "scan requires --ivk with an Ironwood viewing key (uview1… or uivk1…)",
            )?;
            let prepared_ivk = prepare_orchard_ivk(ivk, network)?;

            let include_all = all.unwrap_or(0) == 1;
            let latest_height = client.get_latest_block(ChainSpec::default()).await?.into_inner().height;

            if block_count == 0 {
                return Err("block_count must be greater than 0".into());
            }

            let requested_end = start_block.saturating_add(block_count - 1);
            if requested_end > latest_height {
                return Err(format!(
                    "Requested end block {requested_end} exceeds latest blockchain height {latest_height}"
                ).into());
            }

            let end_block = requested_end;

            // `GetBlockRange` defaults to pruning `CompactBlock.vtx` down to transactions that
            // touch the Sapling/Orchard pools only (service.proto: "If no pool types are
            // specified, the server should default to ... returning only data relevant to the
            // shielded (Sapling and Orchard) pools") — and this protocol version has no Ironwood
            // pool type to opt into at all. Confirmed live against testnet.zec.rocks: for a block
            // whose only shielded content was a coinbase transparent output, `GetBlockRange`
            // returned 1 vtx entry while `GetBlock` returned 2 (the pruned one included). A
            // transaction whose *only* shielded content is an Ironwood bundle — no Sapling,
            // Orchard, or otherwise-qualifying data — would be silently dropped from `vtx` the
            // same way under `GetBlockRange`. `GetBlock` is documented to return "transaction data
            // for all value pools" unconditionally, so blocks are fetched individually here
            // (concurrently, bounded) instead of via the pruned range stream.
            let heights: Vec<u64> = (start_block..=end_block).collect();
            let mut block_fetches = futures::stream::iter(heights.iter().map(|&height| {
                let mut client = client.clone();
                async move {
                    client.get_block(BlockId { height, hash: vec![] }).await
                        .map(|resp| resp.into_inner())
                        .map_err(|e| format!("Failed to fetch block {height}: {e}"))
                }
            }))
            .buffer_unordered(BLOCK_FETCH_CONCURRENCY);

            let mut compact_blocks: std::collections::BTreeMap<u64, lightwallet_protocol::CompactBlock> =
                std::collections::BTreeMap::new();
            while let Some(compact_block) = block_fetches.next().await {
                let compact_block = compact_block?;
                if compact_block.height < start_block || compact_block.height > end_block {
                    return Err(format!(
                        "Server returned block at unexpected height {} (requested range {start_block}..={end_block})",
                        compact_block.height
                    ).into());
                }
                compact_blocks.insert(compact_block.height, compact_block);
            }

            // Every height in the requested range must have been returned exactly once — a gap
            // here would mean the scan result silently omits transactions and must not be
            // treated as complete.
            if compact_blocks.len() != heights.len() {
                return Err(format!(
                    "Expected {} blocks in range {start_block}..={end_block} but only received {}",
                    heights.len(),
                    compact_blocks.len()
                ).into());
            }

            // Verify the fetched blocks form one unbroken chain, guarding against a reorg
            // happening mid-scan producing an inconsistent mix of blocks from different tips.
            // Skipped where either hash is empty, since `hash`/`prevHash` are documented as
            // "if present" (may legitimately be unset by some server implementations).
            let mut prev_hash: Option<&Vec<u8>> = None;
            for compact_block in compact_blocks.values() {
                if let Some(expected_prev) = prev_hash {
                    if !expected_prev.is_empty() && !compact_block.prev_hash.is_empty()
                        && compact_block.prev_hash != *expected_prev
                    {
                        return Err(format!(
                            "Chain discontinuity at block {}: prevHash does not match the previous \
                             block's hash — a reorg likely happened mid-scan, retry the scan",
                            compact_block.height
                        ).into());
                    }
                }
                prev_hash = Some(&compact_block.hash);
            }

            // Fetch every transaction across the whole range with one bounded-concurrency
            // pipeline. Fetching per-block instead (a `try_join_all` inside a sequential loop
            // over blocks) serializes on the slowest transaction of each block and yields almost
            // no parallelism for the common case of 1-2 transactions per block.
            //
            // Each response is parsed and trial-decrypted as soon as it arrives and only the
            // (small) extracted notes are retained, so the raw transaction bytes are dropped
            // immediately and peak memory stays bounded by the concurrency level rather than by
            // the size of the scanned range.
            let tx_requests: Vec<(u64, u64, Vec<u8>)> = compact_blocks
                .values()
                .flat_map(|compact_block| {
                    compact_block.vtx.iter().map(move |compact_tx| {
                        (compact_block.height, compact_tx.index, compact_tx.txid.clone())
                    })
                })
                .collect();

            let mut tx_fetches = futures::stream::iter(tx_requests.into_iter().map(
                |(height, index, txid)| {
                    let mut client = client.clone();
                    async move {
                        let filter = TxFilter { hash: txid.clone(), ..Default::default() };
                        client.get_transaction(filter).await
                            .map(|resp| (height, index, txid.clone(), resp.into_inner()))
                            .map_err(|e| format!(
                                "Failed to download transaction {}: {e}",
                                const_hex::encode(&txid)
                            ))
                    }
                },
            ))
            .buffer_unordered(TX_FETCH_CONCURRENCY);

            // Keyed by (block height, index within block) so output ordering is the canonical
            // chain order regardless of which fetches completed first.
            let mut scanned_txs: std::collections::BTreeMap<(u64, u64), ScanTx> =
                std::collections::BTreeMap::new();

            while let Some(fetched) = tx_fetches.next().await {
                let (height, index, txid, raw_tx_resp) = fetched?;
                let branch_id = BranchId::for_height(&network, to_block_height(height)?);

                let tx = Transaction::read(&mut &raw_tx_resp.data[..], branch_id)
                    .map_err(|e| format!("Failed to parse transaction {}: {}", const_hex::encode(&txid), e))?;

                // Defend against a server bug/inconsistency silently substituting a different
                // transaction's bytes for the one requested — undetected, this would make the
                // real transaction vanish from the scan output instead of raising an error.
                let returned_txid: [u8; 32] = tx.txid().into();
                if returned_txid.as_slice() != txid.as_slice() {
                    return Err(format!(
                        "Server returned transaction {} for requested txid {}",
                        tx.txid(),
                        const_hex::encode(&txid)
                    ).into());
                }

                let mut tx_notes = std::collections::BTreeMap::new();

                if let Some(bundle) = tx.ironwood_bundle() {
                    for (action_idx, action) in bundle.actions().iter().enumerate() {
                        let domain = IronwoodDomain::for_action(action);
                        // Every note this viewing key decrypts is reported, whichever
                        // diversified address it was sent to.
                        //
                        // Filtering on one configured address instead used to drop payments
                        // silently: an incoming viewing key decrypts notes for the whole
                        // account, so a payment to any other diversified address of the same
                        // account was received but never seen — no command, no refund, no
                        // record. Keying on the viewing key alone also means rotating the
                        // published address needs no scanner reconfiguration, and every
                        // independent indexer derives the same set from the published key
                        // rather than from a string each operator has to get right.
                        if let Some((note, _recipient, memo)) = try_note_decryption(&domain, &prepared_ivk, action) {
                            tx_notes.insert(action_idx as u64, ScanNote {
                                amount: note.value().inner(),
                                memo: decode_memo(&memo),
                            });
                        }
                    }
                }

                if !tx_notes.is_empty() {
                    scanned_txs.insert((height, index), ScanTx {
                        tx_id: format!("{}", tx.txid()),
                        tx_block_index: index,
                        notes: tx_notes,
                    });
                }
            }

            let mut results: Vec<ScanBlock> = Vec::new();

            for (block_height, compact_block) in &compact_blocks {
                let block_height = *block_height;
                let block_txs: Vec<ScanTx> = scanned_txs
                    .range((block_height, u64::MIN)..=(block_height, u64::MAX))
                    .map(|(_, tx)| tx.clone())
                    .collect();

                if !block_txs.is_empty() || include_all {
                    let block_confirmations = latest_height.saturating_sub(block_height) + 1;
                    results.push(ScanBlock {
                        block_id: block_height,
                        block_hash: compact_block.hash.clone(),
                        block_time: compact_block.time,
                        confirmations: block_confirmations,
                        txs: block_txs,
                    });
                }
            }

            // Blocks are keyed by height in a BTreeMap and transactions are pushed in `vtx`
            // order, so results are in ascending (block height, tx index) order regardless of
            // the order the concurrent fetches completed in.
            // Serialize directly to stdout to preserve exact order and structure.
            print!("{{");
            for (i, block) in results.iter().enumerate() {
                if i > 0 { print!(","); }
                let block_hash_hex = reverse_hex(&block.block_hash);
                if block.txs.is_empty() {
                    print!(
                        "\"{}\":{{\"hash\":\"{}\",\"time\":{}}}",
                        block.block_id, block_hash_hex, block.block_time
                    );
                } else {
                    print!(
                        "\"{}\":{{\"hash\":\"{}\",\"time\":{},\"confirmations\":{},\"tx\":{{",
                        block.block_id, block_hash_hex, block.block_time, block.confirmations
                    );
                    for (j, tx) in block.txs.iter().enumerate() {
                        if j > 0 { print!(","); }
                        print!("\"{}\":{{\"tx_hash\":\"{}\",\"inputs\":{{", tx.tx_block_index, tx.tx_id);
                        for (k, (&input_idx, note)) in tx.notes.iter().enumerate() {
                            if k > 0 { print!(","); }
                            let memo_escaped = serde_json::to_string(&note.memo)?;
                            print!(
                                "\"{}\":{{\"amount\":{},\"memo\":{}}}",
                                input_idx, note.amount, memo_escaped
                            );
                        }
                        print!("}}}}");
                    }
                    print!("}}}}");
                }
            }
            println!("}}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::SpendingKey;
    use zcash_address::unified::Address as UnifiedAddress;
    use zcash_protocol::consensus::NetworkType;

    /// A real Orchard receiver, derived from a fixed spending key.
    ///
    /// Filler bytes will not do: `address_is_valid` decodes this payload as a curve
    /// point, so a test built from arbitrary bytes would assert the opposite of what
    /// the real pipeline does. Same derivation as the prover's gen_ua_corpus.
    fn orchard_receiver(seed: u8) -> Receiver {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32]))
            .expect("seed is a valid Orchard spending key");
        let raw: [u8; 43] = FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes();
        Receiver::Orchard(raw)
    }

    fn ua(receivers: Vec<Receiver>, net: NetworkType) -> String {
        let addr = UnifiedAddress::try_from_items(receivers).expect("builds a unified address");
        // The same Encoding trait the gate decodes with, so the test exercises the real
        // bech32m + F4Jumble round trip rather than a hand-built string.
        addr.encode(&net)
    }

    // -- the ingest gate ---------------------------------------------------
    //
    // This gate is what stops a command the circuit cannot prove from entering a batch:
    // the registrar shells out to `validateaddress` for every target address, and a batch
    // containing one the guest rejects can never be proved, halting the checkpoint chain
    // until someone edits the database by hand. The properties below are the ones that
    // keep the gate no looser than `zns-core::is_address_valid`.

    #[test]
    fn accepts_an_orchard_ua_on_the_matching_network() {
        assert!(address_is_valid(
            &ua(vec![orchard_receiver(0x11)], NetworkType::Main),
            Network::MainNetwork
        ));
        assert!(address_is_valid(
            &ua(vec![orchard_receiver(0x11)], NetworkType::Test),
            Network::TestNetwork
        ));
    }

    #[test]
    fn accepts_orchard_alongside_other_receivers() {
        // Only Orchard's presence is required; extra receivers are legitimate and common.
        assert!(address_is_valid(
            &ua(
                vec![orchard_receiver(0x12), Receiver::Sapling([3u8; 43]), Receiver::P2pkh([5u8; 20])],
                NetworkType::Main
            ),
            Network::MainNetwork
        ));
    }

    #[test]
    fn rejects_a_ua_without_an_orchard_receiver() {
        // The registrar pays owners in the Orchard pool, so a Sapling-only address is
        // unpayable. The circuit rejects it too - if this gate ever accepted one, the
        // resulting batch would be unprovable.
        assert!(!address_is_valid(
            &ua(vec![Receiver::Sapling([7u8; 43])], NetworkType::Main),
            Network::MainNetwork
        ));
        assert!(!address_is_valid(
            &ua(vec![Receiver::Sapling([8u8; 43]), Receiver::P2pkh([9u8; 20])], NetworkType::Main),
            Network::MainNetwork
        ));
    }

    #[test]
    fn rejects_a_ua_from_the_wrong_network() {
        let mainnet = ua(vec![orchard_receiver(0x13)], NetworkType::Main);
        let testnet = ua(vec![orchard_receiver(0x13)], NetworkType::Test);
        assert!(!address_is_valid(&mainnet, Network::TestNetwork));
        assert!(!address_is_valid(&testnet, Network::MainNetwork));
    }

    #[test]
    fn rejects_an_orchard_receiver_that_is_not_a_curve_point() {
        // Stricter than the circuit, which only checks the receiver is present. Pinned so
        // the extra strictness is a decision rather than an accident: it may only ever be
        // relaxed toward the circuit, never past it.
        assert!(!address_is_valid(
            &ua(vec![Receiver::Orchard([0xABu8; 43])], NetworkType::Main),
            Network::MainNetwork
        ));
    }

    #[test]
    fn rejects_malformed_and_non_unified_addresses() {
        for bad in [
            "",
            "not-an-address",
            "u1notvalidbech32m",
            // A transparent address is not a Unified Address, whatever else it is.
            "t1KfSLZmQrKJ3ymDgvCF6qHYFbtvpEwPYYP",
            // Uppercase: bech32m forbids mixed case, and the registrar requires
            // lowercase canonical form before it ever gets here.
            &ua(vec![orchard_receiver(0x14)], NetworkType::Main).to_uppercase(),
        ] {
            assert!(!address_is_valid(bad, Network::MainNetwork), "accepted {bad:?}");
        }
    }

    /// Cross-checks this gate against the same corpus the circuit is checked against.
    ///
    /// `zns-core`'s `address_corpus` test reads this file too, so a disagreement between
    /// the ingest gate and the guest's rule shows up here rather than as a batch that
    /// cannot be proved. Skipped when the prover checkout is not beside this one; set
    /// UA_CORPUS to point at it explicitly.
    #[test]
    fn agrees_with_the_reference_corpus() {
        let path = std::env::var("UA_CORPUS").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../zcash-name-prover/docs/reference/fixtures/ua_corpus.json"
            )
            .to_string()
        });
        let Ok(raw) = std::fs::read_to_string(&path) else {
            eprintln!("  skipped: no corpus at {path} (set UA_CORPUS to run)");
            return;
        };

        let mut checked = 0usize;
        let mut failures = Vec::new();
        for entry in raw.split("\"addr\":").skip(1) {
            let addr: String =
                serde_json::from_str(entry.split(",\"why\"").next().expect("addr field"))
                    .expect("addr is a JSON string");
            for (key, net) in [
                ("\"mainnet\":", Network::MainNetwork),
                ("\"testnet\":", Network::TestNetwork),
            ] {
                let want = entry
                    .split(key)
                    .nth(1)
                    .map(|t| t.trim_start().starts_with("true"))
                    .expect("verdict for this network");
                let got = address_is_valid(&addr, net);
                if got != want {
                    failures.push(format!("{addr:?} on {net:?}: expected {want}, got {got}"));
                }
                checked += 1;
            }
        }

        assert!(checked > 0, "corpus produced no cases");
        assert!(failures.is_empty(), "{} of {checked} disagree:\n{}", failures.len(), failures.join("\n"));
        eprintln!("  {checked} corpus verdicts agree with the circuit's rule");
    }

    fn memo_with(prefix: &[u8]) -> [u8; 512] {
        let mut memo = [0u8; 512];
        memo[..prefix.len()].copy_from_slice(prefix);
        memo
    }

    #[test]
    fn no_memo_sentinel_decodes_to_empty() {
        // ZIP-302: 0xF6 followed by all zeros means "no memo".
        assert_eq!(decode_memo(&memo_with(&[0xF6])), "");
    }

    #[test]
    fn text_memo_strips_trailing_padding() {
        assert_eq!(decode_memo(&memo_with(b"zns:register:alice")), "zns:register:alice");
    }

    #[test]
    fn text_memo_keeps_bytes_after_embedded_nul() {
        // Truncating at the first zero byte (rather than stripping only trailing padding) would
        // silently drop the second half of a protocol payload.
        let decoded = decode_memo(&memo_with(b"a\x00b"));
        assert_eq!(decoded.len(), 3, "expected embedded NUL to be preserved, got {decoded:?}");
        assert!(decoded.ends_with('b'));
    }

    #[test]
    fn reserved_and_binary_memos_are_not_treated_as_text() {
        // 0xF5 and 0xF7..=0xFF are reserved by ZIP-302 for non-text payloads.
        for first in [0xF5u8, 0xF7, 0xFF] {
            assert!(!memo_is_text(&memo_with(&[first])), "0x{first:02x} must not be text");
        }
        // The whole text range must still be accepted.
        for first in [0x00u8, 0x41, 0xF4] {
            assert!(memo_is_text(&memo_with(&[first])), "0x{first:02x} must be text");
        }
    }

    #[test]
    fn network_parsing_is_strict() {
        assert!(matches!(parse_network("mainnet").unwrap(), Network::MainNetwork));
        assert!(matches!(parse_network("Test").unwrap(), Network::TestNetwork));
        // A typo must fail loudly rather than silently defaulting to mainnet, which would
        // select the wrong consensus branch and make scans return nothing.
        assert!(parse_network("tesnet").is_err());
        assert!(parse_network("regtest").is_err());
    }

    #[test]
    fn reverse_hex_matches_zcash_display_order() {
        assert_eq!(reverse_hex(&[0x01, 0x02, 0x03]), "030201");
    }

    #[test]
    fn block_height_conversion_rejects_out_of_range() {
        assert!(to_block_height(u64::from(u32::MAX) + 1).is_err());
        assert!(to_block_height(4_195_674).is_ok());
    }

    #[test]
    fn local_targets_prefer_plaintext_remote_prefer_tls() {
        assert_eq!(build_urls("127.0.0.1:9067")[0], "http://127.0.0.1:9067");
        assert_eq!(build_urls("testnet.zec.rocks:443")[0], "https://testnet.zec.rocks:443");
        // An explicit scheme must be honoured verbatim, not probed.
        assert_eq!(build_urls("http://example:1"), vec!["http://example:1"]);
    }
}
