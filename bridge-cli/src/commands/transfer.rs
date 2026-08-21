use std::str::FromStr;

use alloy::primitives::{Address as EvmH160, TxHash};
use alloy::signers::local::PrivateKeySigner;
use clap::Subcommand;
use near_bridge_client::{btc::format_max_gas_fee, TransactionOptions};
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{FinTransferArgs, InitTransferArgs, OmniConnector};
use omni_types::{near_events::OmniBridgeEvent, ChainKind, Fee, OmniAddress, TransferId};

use crate::api;
use crate::config::CliConfig;
use crate::connector::{ensure_dry_run_allowed, extract_solana_keypair};

use super::{die, utxo, ChainToken, ChainTx, Ctx, TransferRef};
use solana_sdk::signature::Signer as SolanaSigner;

/// The system program id — `OmniAddress::Sol`'s representation of native SOL.
const SVM_NATIVE_TOKEN: &str = "11111111111111111111111111111111";

/// Message injected into a NEAR `init_transfer` when `--to-hypercore` is set.
///
/// The NEAR omni-bridge parses this string as a `DestinationChainMsg` and keeps
/// only the decoded `DestHexMsg` bytes in the signed `TransferMessagePayload`
/// (`omni-bridge/src/lib.rs`: `DestinationChainMsg::from_json(..).destination_msg()`);
/// anything that doesn't parse to `{"DestHexMsg":"<hex>"}` decodes to empty.
/// On HyperEVM, `OmniBridge.finTransfer` then dispatches purely on
/// `payload.message.length`: empty → 2-arg `mint` (plain HyperEVM ERC20),
/// non-empty → 3-arg `mint` on `HlBridgeToken`, which `_update`s the supply to
/// the system address so HyperCore credits the recipient's spot balance.
///
/// The byte *content* is ignored by the 3-arg `mint` — only its non-emptiness
/// matters. The bytes `636F7265` decode to ASCII `"core"`: a human-readable
/// marker for indexers/logs, and byte-identical to `@omni-bridge/sdk`'s
/// `HYPERLIQUID_MESSAGE` so both SDKs emit the same `DestHexMsg` payload.
const HYPERCORE_DEST_MESSAGE: &str = r#"{"DestHexMsg":"636F7265"}"#;

#[derive(Subcommand, Debug)]
pub enum TransferCmd {
    /// Start a transfer. The source chain is the token's chain prefix; fees
    /// are fetched from the bridge indexer unless given explicitly.
    Init {
        #[clap(
            short,
            long,
            help = "Token to transfer, as <chain>:<address> (e.g. near:usdt.tether-token.near, eth:0x..., sol:...). Determines the source chain; sol:11111111111111111111111111111111 transfers native SOL"
        )]
        token: ChainToken,
        #[clap(short, long, help = "Amount to transfer, in the token's smallest unit")]
        amount: u128,
        #[clap(
            short,
            long,
            help = "Recipient on the destination chain, as <chain>:<address>"
        )]
        recipient: OmniAddress,
        #[clap(
            short,
            long,
            help = "Bridge fee in token units (auto-fetched from the indexer if omitted)"
        )]
        fee: Option<u128>,
        #[clap(
            long,
            help = "Fee in the source chain's native token (auto-fetched from the indexer if omitted)"
        )]
        native_fee: Option<u128>,
        #[clap(
            short,
            long,
            help = "Additional message (JSON format, e.g. '{\"MaxGasFee\": \"400\"}' for BTC transfers)"
        )]
        message: Option<String>,
        #[clap(
            long,
            conflicts_with = "message",
            help = "Deliver to a HyperCore (Hyperliquid L1) spot balance. Only valid for NEAR-originated transfers with an hlevm:0x... recipient"
        )]
        to_hypercore: bool,
    },

    /// HyperCore -> any destination via sendToEvmWithData. An hlevm:0x...
    /// recipient releases directly from the pool on HyperEVM; any other
    /// recipient routes through the OmniBridge.
    Hypercore {
        #[clap(long, help = "Hyperliquid spot token identifier, e.g. PURR:0x<32hex>")]
        token: String,
        #[clap(
            long,
            help = "HlBridgeToken contract address on HyperEVM (resolved from spotMeta if omitted)"
        )]
        hl_token: Option<EvmH160>,
        #[clap(short, long, help = "Amount in bridge ERC20 wei units")]
        amount: u128,
        #[clap(
            long,
            help = "Bridge token decimals (resolved from spotMeta if omitted)"
        )]
        decimals: Option<u8>,
        #[clap(
            short,
            long,
            help = "Recipient OmniAddress: hlevm:0x... (pool release on HyperEVM) or near:... / sol:... / eth:0x... etc. (bridge)"
        )]
        recipient: OmniAddress,
        #[clap(
            short,
            long,
            help = "Bridge fee in bridge ERC20 wei units (ignored when recipient is hlevm:)"
        )]
        fee: Option<u128>,
        #[clap(
            short,
            long,
            help = "Additional message routed through the bridge (ignored when recipient is hlevm:)"
        )]
        message: Option<String>,
        #[clap(long, help = "Override HyperEVM gas limit for the system call")]
        gas_limit: Option<u64>,
    },

    /// Finalize a transfer. Pass the transaction that proves it: the origin
    /// chain's init tx to finalize on NEAR, or the NEAR sign_transfer tx to
    /// finalize on the destination chain (auto-detected from the payload).
    Finalize {
        #[clap(
            short,
            long,
            help = "Proof transaction as <chain>:<hash>. An origin-chain init tx (incl. btc:/zcash: deposits) finalizes on NEAR. A near: tx finalizes on the destination chain: pass the sign_transfer tx, or for BTC/Zcash withdrawals the init tx (runs submit -> MPC sign -> broadcast)"
        )]
        tx: ChainTx,
        #[clap(
            long,
            help = "Destination chain override; auto-derived from the transfer event or the bridge indexer if omitted"
        )]
        destination_chain: Option<ChainKind>,
        #[clap(long, help = "Sender of the NEAR sign_transfer tx (near: proofs only)")]
        sender_id: Option<AccountId>,
        #[clap(long, help = "Use the fast-transfer path (finalizing on NEAR only)")]
        fast: bool,
        #[clap(long, help = "Storage deposit for the token receiver (--fast only)")]
        storage_deposit_amount: Option<u128>,
    },

    /// Sign an initialized transfer on NEAR (fees default to the values
    /// stored in the transfer message)
    Sign {
        #[clap(
            long,
            help = "Transfer to sign, as <origin-chain>:<origin-nonce> (e.g. eth:12345)"
        )]
        transfer: TransferRef,
        #[clap(
            short,
            long,
            help = "Fee in token units (defaults to the transfer's fee)"
        )]
        fee: Option<u128>,
        #[clap(
            long,
            help = "Native token fee (defaults to the transfer's native fee)"
        )]
        native_fee: Option<u128>,
        #[clap(long, help = "Fee recipient account ID")]
        fee_recipient: Option<AccountId>,
    },

    /// Show a transfer's status (bridge indexer lookup by any related tx hash,
    /// or on-chain check by destination nonce)
    Status {
        #[clap(
            short,
            long,
            help = "Any transaction hash that touched the transfer (chain prefix optional)"
        )]
        tx: Option<String>,
        #[clap(long, help = "On-chain check: destination chain of the transfer")]
        destination_chain: Option<ChainKind>,
        #[clap(long, help = "On-chain check: destination nonce of the transfer")]
        nonce: Option<u64>,
        #[clap(
            long,
            help = "On-chain check: origin chain (needed when the destination is NEAR)"
        )]
        origin_chain: Option<ChainKind>,
    },
}

pub async fn run(cmd: TransferCmd, ctx: &Ctx) {
    match cmd {
        TransferCmd::Init {
            token,
            amount,
            recipient,
            fee,
            native_fee,
            message,
            to_hypercore,
        } => {
            init(
                ctx,
                token,
                amount,
                recipient,
                fee,
                native_fee,
                message,
                to_hypercore,
            )
            .await
        }
        TransferCmd::Hypercore {
            token,
            hl_token,
            amount,
            decimals,
            recipient,
            fee,
            message,
            gas_limit,
        } => {
            // Signs and POSTs a Hyperliquid action straight to the exchange
            // API; never goes through a dry-run-aware client.
            ensure_dry_run_allowed(ctx, ChainKind::HyperEvm);
            ctx.connector()
                .init_transfer(InitTransferArgs::HyperCoreTransfer {
                    token,
                    hl_bridge_token: hl_token,
                    amount,
                    decimals,
                    recipient,
                    fee: fee.unwrap_or_default(),
                    message: message.unwrap_or_default(),
                    gas_limit,
                })
                .await
                .unwrap();
        }
        TransferCmd::Finalize {
            tx,
            destination_chain,
            sender_id,
            fast,
            storage_deposit_amount,
        } => {
            finalize(
                ctx,
                tx,
                destination_chain,
                sender_id,
                fast,
                storage_deposit_amount,
            )
            .await;
        }
        TransferCmd::Sign {
            transfer,
            fee,
            native_fee,
            fee_recipient,
        } => sign(ctx, transfer, fee, native_fee, fee_recipient).await,
        TransferCmd::Status {
            tx,
            destination_chain,
            nonce,
            origin_chain,
        } => status(ctx, tx, destination_chain, nonce, origin_chain).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn init(
    ctx: &Ctx,
    token: ChainToken,
    amount: u128,
    recipient: OmniAddress,
    fee: Option<u128>,
    native_fee: Option<u128>,
    message: Option<String>,
    to_hypercore: bool,
) {
    if to_hypercore {
        if token.chain != ChainKind::Near {
            die("--to-hypercore is only supported for NEAR-originated transfers");
        }
        if recipient.get_chain() != ChainKind::HyperEvm {
            die(format!(
                "--to-hypercore requires an hlevm:0x... recipient, got {recipient}"
            ));
        }
    }

    match token.chain {
        ChainKind::Near => {
            init_near(
                ctx,
                &token.address,
                amount,
                recipient,
                fee,
                native_fee,
                message,
                to_hypercore,
            )
            .await;
        }
        chain @ (ChainKind::Eth
        | ChainKind::Arb
        | ChainKind::Base
        | ChainKind::Bnb
        | ChainKind::Pol
        | ChainKind::HyperEvm
        | ChainKind::Abs) => {
            ensure_dry_run_allowed(ctx, chain);

            let (fee, native_fee) = match (fee, native_fee) {
                (Some(f), Some(nf)) => (f, nf),
                (Some(f), None) => (f, 0),
                (None, Some(nf)) => (0, nf),
                _ => {
                    let (f, nf, _) =
                        resolve_evm_fees(chain, &ctx.config, &token.address, amount, &recipient)
                            .await
                            .unwrap_or_else(|err| die(err));
                    (f, nf)
                }
            };

            ctx.connector()
                .init_transfer(InitTransferArgs::EvmInitTransfer {
                    chain_kind: chain,
                    token: token.address,
                    amount,
                    recipient,
                    fee: Fee {
                        fee: fee.into(),
                        native_fee: native_fee.into(),
                    },
                    message: message.unwrap_or_default(),
                    tx_nonce: None,
                })
                .await
                .unwrap();
        }
        chain @ (ChainKind::Sol | ChainKind::Fogo) => {
            ensure_dry_run_allowed(ctx, chain);
            init_svm(
                ctx,
                chain,
                &token.address,
                amount,
                recipient,
                fee,
                native_fee,
                message,
            )
            .await;
        }
        ChainKind::Strk => {
            ensure_dry_run_allowed(ctx, ChainKind::Strk);
            let (fee, native_fee) = (fee.unwrap_or(0), native_fee.unwrap_or(0));
            ctx.connector()
                .init_transfer(InitTransferArgs::StarknetInitTransfer {
                    token: token.address,
                    amount,
                    recipient: recipient.to_string(),
                    fee,
                    native_fee,
                    message: message.unwrap_or_default(),
                })
                .await
                .unwrap();
        }
        ChainKind::Aptos => {
            ensure_dry_run_allowed(ctx, ChainKind::Aptos);
            let (fee, native_fee) = (fee.unwrap_or(0), native_fee.unwrap_or(0));
            ctx.connector()
                .init_transfer(InitTransferArgs::AptosInitTransfer {
                    token: token.address,
                    amount,
                    recipient: recipient.to_string(),
                    fee,
                    native_fee,
                    message: message.unwrap_or_default(),
                })
                .await
                .unwrap();
        }
        ChainKind::Btc | ChainKind::Zcash => die(
            "Bitcoin/Zcash deposits start on-chain: request an address with \
             `utxo deposit-address`, send funds to it, then run `utxo finalize-deposit`",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn init_near(
    ctx: &Ctx,
    token: &str,
    amount: u128,
    recipient: OmniAddress,
    fee: Option<u128>,
    native_fee: Option<u128>,
    message: Option<String>,
    to_hypercore: bool,
) {
    let token: AccountId = token
        .parse()
        .unwrap_or_else(|e| die(format!("invalid NEAR token account: {e}")));

    let (_, native_fee, gas_fee) = match (fee, native_fee) {
        (Some(f), Some(nf)) => (f, nf, None),
        (Some(f), None) => (f, 0, None),
        (None, Some(nf)) => (0, nf, None),
        _ => {
            let api_url = ctx.indexer_api_url();

            let sender = ctx
                .config
                .near_signer
                .as_deref()
                .unwrap_or_else(|| die("getting fee: near_signer not available"))
                .parse()
                .map(OmniAddress::Near)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|e| die(format!("getting fee: failed to parse near_signer: {e}")));

            let token_addr = OmniAddress::Near(token.clone());
            fetch_indexer_fees(api_url, sender, token_addr.to_string(), amount, &recipient)
                .await
                .unwrap_or_else(|e| die(format!("failed to get fee from indexer: {e}")))
        }
    };

    let mut message = message.unwrap_or_default();
    if to_hypercore {
        message = HYPERCORE_DEST_MESSAGE.to_string();
    } else if message.is_empty()
        && matches!(recipient.get_chain(), ChainKind::Btc | ChainKind::Zcash)
    {
        if let Some(gas_fee) = gas_fee {
            message = format_max_gas_fee(u64::try_from(gas_fee).unwrap());
        }
    }

    ctx.connector()
        .init_transfer(InitTransferArgs::NearInitTransfer {
            token,
            amount,
            recipient,
            fee: None,
            native_fee: Some(native_fee),
            message,
            transaction_options: TransactionOptions::default(),
        })
        .await
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn init_svm(
    ctx: &Ctx,
    chain: ChainKind,
    token: &str,
    amount: u128,
    recipient: OmniAddress,
    fee: Option<u128>,
    native_fee: Option<u128>,
    message: Option<String>,
) {
    let native_fee = native_fee
        .map(svm_native_fee_to_u64)
        .transpose()
        .unwrap_or_else(|e| die(e));

    if token == SVM_NATIVE_TOKEN {
        // The on-chain `init_transfer_sol` instruction requires `fee == 0`
        // (the bridge service fee is rolled into `native_fee`, which is
        // debited together with `amount` from the user's SOL balance).
        let native_fee = match native_fee {
            Some(nf) => nf,
            None => {
                let (_, nf, _) = resolve_svm_fees(
                    chain,
                    ctx,
                    &format!("{}:{SVM_NATIVE_TOKEN}", svm_prefix(chain)),
                    amount,
                    &recipient,
                )
                .await
                .unwrap_or_else(|e| die(e));
                nf
            }
        };

        ctx.connector()
            .init_transfer(InitTransferArgs::SvmInitTransferSol {
                chain_kind: chain,
                amount,
                recipient,
                fee: 0,
                native_fee,
                message: String::new(),
            })
            .await
            .unwrap();
        return;
    }

    let (fee, native_fee) = match (fee, native_fee) {
        (Some(f), Some(nf)) => (f, nf),
        (Some(f), None) => (f, 0),
        (None, Some(nf)) => (0, nf),
        _ => {
            let (f, nf, _) = resolve_svm_fees(
                chain,
                ctx,
                &format!("{}:{token}", svm_prefix(chain)),
                amount,
                &recipient,
            )
            .await
            .unwrap_or_else(|e| die(e));
            (f, nf)
        }
    };

    ctx.connector()
        .init_transfer(InitTransferArgs::SvmInitTransfer {
            chain_kind: chain,
            token: token
                .parse()
                .unwrap_or_else(|e| die(format!("invalid SVM token mint: {e}"))),
            amount,
            recipient,
            fee,
            native_fee,
            message: message.unwrap_or_default(),
        })
        .await
        .unwrap();
}

async fn finalize(
    ctx: &Ctx,
    tx: ChainTx,
    destination_chain: Option<ChainKind>,
    sender_id: Option<AccountId>,
    fast: bool,
    storage_deposit_amount: Option<u128>,
) {
    match tx.chain {
        ChainKind::Near => {
            if fast {
                die("--fast applies when finalizing on NEAR from an origin-chain tx");
            }
            finalize_from_near(ctx, &tx.hash, sender_id).await;
        }
        chain @ (ChainKind::Btc | ChainKind::Zcash) => {
            if fast {
                die(
                    "for fast finalize of a UTXO deposit use `utxo fast-finalize-deposit` \
                     (it needs the original recipient and fee)",
                );
            }
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            utxo::finalize_deposit_auto(ctx, chain, &tx.hash).await;
        }
        origin => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            let connector = ctx.connector();

            if fast {
                connector
                    .near_fast_transfer(
                        origin,
                        tx.hash,
                        storage_deposit_amount,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();
                return;
            }

            let destination =
                resolve_destination_chain(ctx, &connector, origin, &tx.hash, destination_chain)
                    .await;

            let storage_deposit_actions = connector
                .get_storage_deposit_actions_for_tx(origin, tx.hash.clone())
                .await
                .unwrap();

            match origin {
                ChainKind::Eth => {
                    connector
                        .fin_transfer(FinTransferArgs::NearFinTransferWithEvmProof {
                            chain_kind: origin,
                            destination_chain: destination,
                            tx_hash: TxHash::from_str(&tx.hash)
                                .unwrap_or_else(|e| die(format!("invalid tx hash: {e}"))),
                            storage_deposit_actions,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                ChainKind::Arb
                | ChainKind::Base
                | ChainKind::Bnb
                | ChainKind::Pol
                | ChainKind::HyperEvm
                | ChainKind::Sol
                | ChainKind::Fogo => {
                    let vaa = connector
                        .wormhole_get_vaa_by_tx_hash(tx.hash.clone())
                        .await
                        .unwrap();

                    connector
                        .fin_transfer(FinTransferArgs::NearFinTransferWithVaa {
                            chain_kind: origin,
                            destination_chain: destination,
                            storage_deposit_actions,
                            vaa,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                ChainKind::Abs | ChainKind::Strk | ChainKind::Aptos => {
                    connector
                        .fin_transfer(FinTransferArgs::NearFinTransferWithMpcProof {
                            chain_kind: origin,
                            destination_chain: destination,
                            storage_deposit_actions,
                            tx_hash: tx.hash,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                ChainKind::Near | ChainKind::Btc | ChainKind::Zcash => unreachable!(),
            }
        }
    }
}

/// Destination chain of a transfer initialized by `tx_hash` on `origin`:
/// explicit flag > origin-chain transfer event > bridge indexer.
async fn resolve_destination_chain(
    ctx: &Ctx,
    connector: &OmniConnector,
    origin: ChainKind,
    tx_hash: &str,
    explicit: Option<ChainKind>,
) -> ChainKind {
    if let Some(chain) = explicit {
        return chain;
    }

    let from_event = match origin {
        chain if chain.is_evm_chain() => match TxHash::from_str(tx_hash) {
            Ok(hash) => connector
                .evm_get_transfer_event(chain, hash)
                .await
                .ok()
                .and_then(|event| event.recipient.parse::<OmniAddress>().ok())
                .map(|recipient| recipient.get_chain()),
            Err(_) => None,
        },
        ChainKind::Sol | ChainKind::Fogo => match tx_hash.parse() {
            Ok(signature) => connector
                .svm_get_transfer_event(origin, &signature)
                .await
                .ok()
                .and_then(|event| event.recipient.parse::<OmniAddress>().ok())
                .map(|recipient| recipient.get_chain()),
            Err(_) => None,
        },
        _ => None,
    };

    if let Some(chain) = from_event {
        tracing::info!("Destination chain (from transfer event): {chain:?}");
        return chain;
    }

    if let Some(api_url) = ctx.config.bridge_indexer_api_url.as_deref() {
        if let Ok(transfers) = api::fetch_transfers_by_tx(api_url, tx_hash).await {
            let mut destinations = transfers
                .iter()
                .filter_map(|t| t.destination_chain.as_deref())
                .filter_map(|c| ChainKind::from_str(c).ok());
            if let Some(chain) = destinations.next() {
                tracing::info!("Destination chain (from bridge indexer): {chain:?}");
                return chain;
            }
        }
    }

    die("could not determine the destination chain; pass --destination-chain")
}

async fn finalize_from_near(ctx: &Ctx, near_tx_hash: &str, sender_id: Option<AccountId>) {
    let connector = ctx.connector();
    let tx_hash = CryptoHash::from_str(near_tx_hash)
        .unwrap_or_else(|e| die(format!("invalid NEAR tx hash: {e}")));

    let near_bridge_client = connector.near_bridge_client().unwrap();

    let transfer_log = match near_bridge_client
        .extract_transfer_log(tx_hash, sender_id.clone(), "SignTransferEvent")
        .await
    {
        Ok(log) => log,
        Err(sign_err) => {
            // Not a sign_transfer tx. If it's an init_transfer, either run the
            // NEAR→UTXO withdrawal leg (which has no sign_transfer step) or
            // tell the user the exact next command.
            if let Ok(init_log) = near_bridge_client
                .extract_transfer_log(tx_hash, sender_id.clone(), "InitTransferEvent")
                .await
            {
                if let Ok(OmniBridgeEvent::InitTransferEvent { transfer_message }) =
                    serde_json::from_str(&init_log)
                {
                    let destination = transfer_message.recipient.get_chain();
                    if matches!(destination, ChainKind::Btc | ChainKind::Zcash) {
                        finalize_utxo_withdrawal(ctx, &connector, destination, tx_hash, sender_id)
                            .await;
                        return;
                    }
                    die(format!(
                        "this transaction initialized a transfer to {destination:?}; the transfer \
                         must be signed first: run `transfer sign --transfer near:{}` and finalize \
                         with the sign transaction",
                        transfer_message.origin_nonce
                    ));
                }
            }
            die(format!(
                "no SignTransferEvent found in {near_tx_hash}: {sign_err}"
            ));
        }
    };

    let event: OmniBridgeEvent = serde_json::from_str(&transfer_log)
        .unwrap_or_else(|e| die(format!("failed to parse SignTransferEvent: {e}")));
    let OmniBridgeEvent::SignTransferEvent {
        ref message_payload,
        ..
    } = event
    else {
        die("extracted log is not a SignTransferEvent");
    };

    let destination = message_payload.recipient.get_chain();
    let token_address = message_payload.token_address.to_string();
    tracing::info!("Finalizing transfer on {destination:?}");

    match destination {
        chain @ (ChainKind::Eth
        | ChainKind::Arb
        | ChainKind::Base
        | ChainKind::Bnb
        | ChainKind::Pol
        | ChainKind::HyperEvm
        | ChainKind::Abs) => {
            ensure_dry_run_allowed(ctx, chain);
            connector
                .fin_transfer(FinTransferArgs::EvmFinTransfer {
                    chain_kind: chain,
                    event,
                    tx_nonce: None,
                })
                .await
                .unwrap();
        }
        ChainKind::Sol | ChainKind::Fogo => {
            ensure_dry_run_allowed(ctx, destination);
            // The signed payload's token_address is the destination-chain
            // token: for SVM chains that's the mint (the system program id —
            // Pubkey::default() — for native SOL, which routes to
            // finalize_transfer_sol downstream).
            let svm_token = token_address
                .split_once(':')
                .map_or(token_address.as_str(), |(_, addr)| addr)
                .parse()
                .unwrap_or_else(|e| {
                    die(format!(
                        "signed payload token '{token_address}' is not an SVM mint: {e}"
                    ))
                });
            connector
                .svm_finalize_transfer_with_event(destination, event, svm_token)
                .await
                .unwrap();
        }
        ChainKind::Strk => {
            ensure_dry_run_allowed(ctx, ChainKind::Strk);
            connector
                .fin_transfer(FinTransferArgs::StarknetFinTransferWithTxHash {
                    near_tx_hash: tx_hash,
                    sender_id,
                })
                .await
                .unwrap();
        }
        ChainKind::Aptos => {
            ensure_dry_run_allowed(ctx, ChainKind::Aptos);
            connector
                .fin_transfer(FinTransferArgs::AptosFinTransferWithTxHash {
                    near_tx_hash: tx_hash,
                    sender_id,
                })
                .await
                .unwrap();
        }
        ChainKind::Near => die(
            "this transfer's destination is NEAR; finalize it with the origin-chain init \
             transaction instead",
        ),
        ChainKind::Btc | ChainKind::Zcash => die(
            "NEAR→BTC/Zcash withdrawals are finalized via `utxo submit-transfer`, `utxo sign`, \
             then `utxo broadcast`",
        ),
    }
}

/// Matches the `--change-reserve` default of `utxo submit-transfer`.
const DEFAULT_CHANGE_RESERVE: u128 = 5000;

/// NEAR→BTC/Zcash withdrawal leg: build the UTXO transaction on the connector
/// (submit), request the MPC signature for every input, then broadcast to the
/// UTXO chain. Each step's tx is logged so a failed run can be resumed with
/// the granular `utxo` commands.
async fn finalize_utxo_withdrawal(
    ctx: &Ctx,
    connector: &OmniConnector,
    chain: ChainKind,
    init_tx_hash: CryptoHash,
    sender_id: Option<AccountId>,
) {
    // The final step broadcasts to the UTXO chain, which has no dry-run
    // representation — reject before submitting anything.
    ensure_dry_run_allowed(ctx, chain);
    let chain_name = if chain == ChainKind::Btc {
        "btc"
    } else {
        "zcash"
    };

    tracing::info!("Destination is {chain:?}; running submit -> sign -> broadcast");

    let submit_tx = connector
        .near_submit_btc_transfer_with_tx_hash(
            chain,
            init_tx_hash,
            sender_id,
            None,
            TransactionOptions::default(),
            Some(DEFAULT_CHANGE_RESERVE),
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| {
            die(format!(
                "submit_btc_transfer failed: {e}. If the withdrawal was already submitted (e.g. \
                 by the relayer), continue with `utxo sign --chain {chain_name} --pending-id <id>` \
                 and `utxo broadcast`; `transfer status` shows the transfer's progress"
            ))
        });
    tracing::info!("Submitted UTXO withdrawal transaction: {submit_tx}");

    let near_bridge_client = connector.near_bridge_client().unwrap();

    // The submit tx's generate_btc_pending_info event carries the pending id;
    // the pending info's vutxos are the inputs the MPC signs one by one.
    let pending_id = extract_btc_pending_id(near_bridge_client, submit_tx).await;
    let inputs = near_bridge_client
        .get_btc_pending_info(chain, pending_id.clone())
        .await
        .unwrap_or_else(|e| {
            die(format!(
                "failed to fetch pending tx info for {pending_id}: {e}"
            ))
        })
        .vutxos
        .len()
        .max(1);

    let mut last_sign_tx = None;
    for index in 0..inputs {
        let sign_index = u64::try_from(index).unwrap();
        let sign_tx = connector
            .near_sign_btc_transaction(
                chain,
                pending_id.clone(),
                sign_index,
                TransactionOptions::default(),
            )
            .await
            .unwrap_or_else(|e| {
                die(format!(
                    "MPC signing failed for input {index} of {inputs}: {e}. Resume with `utxo \
                     sign --chain {chain_name} --pending-id {pending_id} --sign-index {index}` \
                     for this and any remaining inputs, then `utxo broadcast --chain \
                     {chain_name} --near-tx <last sign tx> --relayer <near signer>`"
                ))
            });
        tracing::info!("Signed input {} of {inputs}: {sign_tx}", index + 1);
        last_sign_tx = Some(sign_tx);
    }
    let last_sign_tx = last_sign_tx.expect("at least one input");

    // We sent the sign tx ourselves, so the tx-status lookup inside
    // btc_fin_transfer must use our signer, not the default satoshi relayer.
    let relayer = ctx.config.near_signer.as_deref().map(|signer| {
        signer
            .parse()
            .unwrap_or_else(|e| die(format!("invalid NEAR signer account: {e}")))
    });
    let btc_tx_hash = connector
        .btc_fin_transfer(chain, last_sign_tx, relayer)
        .await
        .unwrap_or_else(|e| {
            die(format!(
                "broadcast failed: {e}. Retry with `utxo broadcast --chain {chain_name} \
                 --near-tx {last_sign_tx} --relayer <near signer>`"
            ))
        });

    tracing::info!(
        "Broadcast to {chain:?}: {btc_tx_hash}. After confirmations the relayer verifies it on \
         NEAR (or run `utxo verify-withdraw --chain {chain_name} --tx {btc_tx_hash}`)"
    );
}

async fn extract_btc_pending_id(
    client: &near_bridge_client::NearBridgeClient,
    submit_tx: CryptoHash,
) -> String {
    let log = client
        .extract_transfer_log(submit_tx, None, "generate_btc_pending_info")
        .await
        .unwrap_or_else(|e| {
            die(format!(
                "no generate_btc_pending_info event in {submit_tx}: {e}"
            ))
        });
    let json = log.strip_prefix("EVENT_JSON:").unwrap_or(&log);
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or_else(|e| {
        die(format!(
            "failed to parse generate_btc_pending_info event: {e}"
        ))
    });
    value["data"][0]["btc_pending_id"]
        .as_str()
        .unwrap_or_else(|| die("btc_pending_id not found in generate_btc_pending_info event"))
        .to_string()
}

async fn sign(
    ctx: &Ctx,
    transfer: TransferRef,
    fee: Option<u128>,
    native_fee: Option<u128>,
    fee_recipient: Option<AccountId>,
) {
    let connector = ctx.connector();
    let transfer_id = TransferId {
        origin_chain: transfer.origin_chain,
        origin_nonce: transfer.origin_nonce,
    };

    let (fee, native_fee) = match (fee, native_fee) {
        (Some(f), Some(nf)) => (f, nf),
        _ => {
            let message = connector
                .near_get_transfer_message(transfer_id)
                .await
                .unwrap_or_else(|e| die(format!("failed to fetch transfer message: {e}")));
            (
                fee.unwrap_or(message.fee.fee.0),
                native_fee.unwrap_or(message.fee.native_fee.0),
            )
        }
    };

    // A nonzero fee needs a recipient; the signer collecting it is the
    // standard relayer arrangement, so default to that.
    let fee_recipient =
        fee_recipient.or_else(|| {
            if fee == 0 && native_fee == 0 {
                return None;
            }
            let signer: AccountId = ctx
            .config
            .near_signer
            .as_deref()
            .unwrap_or_else(|| {
                die("the transfer has a nonzero fee: pass --fee-recipient (or configure the NEAR \
                     signer, which is used as the default fee recipient)")
            })
            .parse()
            .unwrap_or_else(|e| die(format!("invalid NEAR signer account: {e}")));
            tracing::info!("Defaulting fee recipient to the signer: {signer}");
            Some(signer)
        });

    connector
        .near_sign_transfer(
            transfer_id,
            fee_recipient,
            Some(Fee {
                fee: fee.into(),
                native_fee: native_fee.into(),
            }),
            TransactionOptions::default(),
        )
        .await
        .unwrap();
}

async fn status(
    ctx: &Ctx,
    tx: Option<String>,
    destination_chain: Option<ChainKind>,
    nonce: Option<u64>,
    origin_chain: Option<ChainKind>,
) {
    if let Some(tx) = tx {
        // The indexer lookup is chain-agnostic; accept both bare hashes and
        // <chain>:<hash> references.
        let hash = tx.split_once(':').map_or(tx.as_str(), |(_, hash)| hash);
        let transfers = api::fetch_transfers_by_tx(ctx.indexer_api_url(), hash)
            .await
            .unwrap_or_else(|e| die(e));

        if transfers.is_empty() {
            println!("No transfer found for transaction {hash}");
            return;
        }

        for transfer in transfers {
            print_transfer(&transfer);
        }
        return;
    }

    if let (Some(destination_chain), Some(nonce)) = (destination_chain, nonce) {
        let finalised = ctx
            .connector()
            .is_transfer_finalised(origin_chain, destination_chain, nonce)
            .await
            .unwrap();
        println!("finalised: {finalised}");
        return;
    }

    die("pass --tx <hash> for an indexer lookup, or --destination-chain and --nonce for an on-chain check");
}

fn print_transfer(transfer: &api::Transfer) {
    println!("status: {}", transfer.status);

    let route = format!(
        "{} -> {}",
        transfer.origin_chain.as_deref().unwrap_or("?"),
        transfer.destination_chain.as_deref().unwrap_or("?")
    );
    println!("  route:       {route}");

    let field = |name: &str, value: &Option<String>| {
        if let Some(value) = value {
            println!("  {name:<13}{value}");
        }
    };
    field("sender:", &transfer.sender);
    field("recipient:", &transfer.recipient);
    field("token:", &transfer.token_id);
    field("amount:", &transfer.amount);
    field("fee:", &transfer.fee);
    field("native fee:", &transfer.native_fee);
    if let Some(nonce) = transfer.destination_nonce {
        println!("  dest nonce:  {nonce}");
    }

    let step = |name: &str, tx: Option<&api::TransactionRef>| {
        if let Some(tx) = tx {
            println!("  {name:<22}{}:{}", tx.chain, tx.transaction_hash);
        }
    };
    step("initialised:", transfer.initialised.as_ref());
    for signed in &transfer.signed {
        step("signed:", Some(signed));
    }
    step(
        "fast finalised (near):",
        transfer.fast_finalised_on_near.as_ref(),
    );
    step("finalised (near):", transfer.finalised_on_near.as_ref());
    step("fast finalised:", transfer.fast_finalised.as_ref());
    step("finalised:", transfer.finalised.as_ref());
    step("claimed:", transfer.claimed.as_ref());
}

fn svm_prefix(chain: ChainKind) -> &'static str {
    match chain {
        ChainKind::Sol => "sol",
        ChainKind::Fogo => "fogo",
        _ => unreachable!("not an SVM chain: {chain:?}"),
    }
}

fn svm_native_fee_to_u64(fee: u128) -> Result<u64, String> {
    u64::try_from(fee).map_err(|_| format!("SVM native_fee {fee} exceeds u64::MAX"))
}

async fn fetch_indexer_fees(
    api_url: &str,
    sender: String,
    token: String,
    amount: u128,
    recipient: &OmniAddress,
) -> Result<(u128, u128, Option<u128>), String> {
    let fee = api::fetch_transfer_fee(
        api_url,
        &sender,
        &recipient.to_string(),
        &token,
        Some(amount),
    )
    .await
    .map_err(|e| format!("Failed to fetch transfer fee: {e}"))?;

    let transferred_fee = fee.transferred_token_fee.map(|v| v.0).unwrap_or_default();

    Ok((
        transferred_fee,
        fee.native_token_fee.0,
        fee.gas_fee.map(|v| v.0),
    ))
}

fn derive_evm_sender(chain: ChainKind, config: &CliConfig) -> Result<String, String> {
    let pk = match chain {
        ChainKind::Eth => &config.eth_private_key,
        ChainKind::Base => &config.base_private_key,
        ChainKind::Arb => &config.arb_private_key,
        ChainKind::Bnb => &config.bnb_private_key,
        ChainKind::Pol => &config.pol_private_key,
        ChainKind::HyperEvm => &config.hyperevm_private_key,
        ChainKind::Abs => &config.abs_private_key,
        _ => return Err(format!("Unsupported EVM chain: {chain:?}")),
    }
    .as_ref()
    .ok_or("Private key not configured")?;

    let wallet: PrivateKeySigner = pk.parse().map_err(|e| format!("Invalid key: {e}"))?;
    evm_address_to_omni(chain, &format!("{:?}", wallet.address()))
}

fn evm_address_to_omni(chain: ChainKind, address: &str) -> Result<String, String> {
    let evm: EvmH160 = address
        .parse()
        .map_err(|e| format!("Invalid EVM address {address}: {e}"))?;
    let omni = OmniAddress::new_from_evm_address(chain, omni_types::H160(evm.into()))
        .map_err(|e| format!("Unsupported EVM chain for address: {e}"))?;
    Ok(omni.to_string())
}

fn derive_svm_sender(chain: ChainKind, ctx: &Ctx) -> Result<String, String> {
    let config = &ctx.config;
    if ctx.dry_run {
        let public_key = match chain {
            ChainKind::Sol => config
                .solana_public_key
                .as_ref()
                .ok_or("solana_public_key not set")?,
            ChainKind::Fogo => config
                .fogo_public_key
                .as_ref()
                .ok_or("fogo_public_key not set")?,
            _ => return Err(format!("not an SVM chain: {chain:?}")),
        };
        let public_key: solana_sdk::pubkey::Pubkey = public_key
            .parse()
            .map_err(|e| format!("invalid SVM public key ({public_key}): {e}"))?;
        return Ok(format!("{}:{public_key}", svm_prefix(chain)));
    }

    let kp = match chain {
        ChainKind::Sol => config
            .solana_keypair
            .as_ref()
            .ok_or("solana_keypair not set")?,
        ChainKind::Fogo => config.fogo_keypair.as_ref().ok_or("fogo_keypair not set")?,
        _ => return Err(format!("not an SVM chain: {chain:?}")),
    };
    let keypair = extract_solana_keypair(kp);
    Ok(format!("{}:{}", svm_prefix(chain), keypair.pubkey()))
}

async fn resolve_evm_fees(
    chain: ChainKind,
    config: &CliConfig,
    token: &str,
    amount: u128,
    recipient: &OmniAddress,
) -> Result<(u128, u128, Option<u128>), String> {
    let api_url = config
        .bridge_indexer_api_url
        .as_deref()
        .ok_or_else(|| "bridge_indexer_api_url must be set to auto-calculate fees".to_string())?;

    let sender = derive_evm_sender(chain, config)?;
    let token = evm_address_to_omni(chain, token)?;

    fetch_indexer_fees(api_url, sender, token, amount, recipient).await
}

async fn resolve_svm_fees(
    chain: ChainKind,
    ctx: &Ctx,
    token: &str,
    amount: u128,
    recipient: &OmniAddress,
) -> Result<(u128, u64, Option<u128>), String> {
    let api_url = ctx
        .config
        .bridge_indexer_api_url
        .as_deref()
        .ok_or_else(|| "bridge_indexer_api_url must be set to auto-calculate fees".to_string())?;

    let sender = derive_svm_sender(chain, ctx)?;
    let token_addr: OmniAddress = token
        .parse()
        .map_err(|err| format!("Failed to parse token address for fee calculation: {err}"))?;

    let (fee, native_fee, gas_fee) =
        fetch_indexer_fees(api_url, sender, token_addr.to_string(), amount, recipient).await?;

    let native_fee = svm_native_fee_to_u64(native_fee)?;

    Ok((fee, native_fee, gas_fee))
}
