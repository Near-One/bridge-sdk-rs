use std::str::FromStr;

use clap::Subcommand;
use near_bridge_client::{
    btc::{DepositMsg, SafeDepositMsg},
    TransactionOptions,
};
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{BtcDepositArgs, FinTransferArgs, OmniConnector};
use omni_types::{ChainKind, OmniAddress};
use utxo_bridge_client::types::PrefetchedTxData;

use crate::connector::ensure_dry_run_allowed;

use super::{die, Ctx};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum UTXOChainArg {
    Btc,
    Zcash,
}

impl From<UTXOChainArg> for ChainKind {
    fn from(value: UTXOChainArg) -> Self {
        match value {
            UTXOChainArg::Btc => ChainKind::Btc,
            UTXOChainArg::Zcash => ChainKind::Zcash,
        }
    }
}

/// Recipient of a UTXO-chain deposit: `<chain>:<address>` routes via the Omni
/// Bridge, a bare NEAR account makes a direct deposit.
#[derive(Clone, Debug)]
pub enum BtcRecipient {
    Direct(AccountId),
    Omni(OmniAddress),
}

impl FromStr for BtcRecipient {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            OmniAddress::from_str(s).map(Self::Omni)
        } else {
            AccountId::from_str(s)
                .map(Self::Direct)
                .map_err(|e| e.to_string())
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum UtxoCmd {
    /// Get a deposit address for transferring BTC/ZEC to a recipient
    DepositAddress {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Transfer recipient as <chain>:<address>")]
        recipient: OmniAddress,
        #[clap(long, help = "Refund address on the UTXO chain")]
        refund_address: Option<String>,
        #[clap(short, long, help = "Omni Bridge fee in satoshi", default_value = "0")]
        fee: u128,
        #[clap(
            long,
            help = "Derive the deposit address via the UTXO connector contract view method instead of the bridge indexer service"
        )]
        from_contract: bool,
    },

    /// Finalize a BTC/ZEC deposit on NEAR. With no --recipient, the deposit
    /// message and output index are auto-discovered from the bridge indexer
    FinalizeDeposit {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Deposit tx hash on the UTXO chain")]
        tx: String,
        #[clap(
            short,
            long,
            help = "Index of the deposit output. If omitted, auto-resolved (matched against the deposit address derived from the recipient/fee/msg, or — with no --recipient — by asking the bridge indexer which output is a tracked deposit address). Pass it when the tx has multiple tracked outputs"
        )]
        vout: Option<usize>,
        #[clap(
            short,
            long,
            help = "Deposit recipient: <chain>:<address> routes via the Omni Bridge, a bare NEAR account makes a direct deposit. If omitted, looked up from the bridge indexer by the tx's output address"
        )]
        recipient: Option<BtcRecipient>,
        #[clap(long, help = "Refund address on the UTXO chain")]
        refund_address: Option<String>,
        #[clap(
            short,
            long,
            help = "Omni Bridge fee in satoshi (used only with a chain-prefixed recipient)",
            default_value = "0"
        )]
        fee: u128,
        #[clap(
            long,
            help = "Optional msg set as SafeDepositMsg.msg (only valid with a direct NEAR recipient)"
        )]
        msg: Option<String>,
    },

    /// Fast-finalize a BTC/ZEC deposit on NEAR (relayer fronts the funds)
    FastFinalizeDeposit {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Deposit tx hash on the UTXO chain")]
        tx: String,
        #[clap(short, long, help = "Transfer recipient as <chain>:<address>")]
        recipient: OmniAddress,
        #[clap(long, help = "Refund address on the UTXO chain")]
        refund_address: Option<String>,
        #[clap(short, long, help = "Transfer fee")]
        fee: u128,
        #[clap(long, help = "Storage deposit amount for the token receiver")]
        storage_deposit_amount: Option<u128>,
    },

    /// Build the UTXO withdrawal tx for a signed NEAR transfer (submit_btc_transfer)
    SubmitTransfer {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(long, help = "NEAR tx hash of the init transfer")]
        near_tx: String,
        #[clap(short, long, help = "Sender of the init transfer on NEAR")]
        sender_id: Option<AccountId>,
        #[clap(short, long, help = "Fee rate on the UTXO chain")]
        fee_rate: Option<u64>,
        #[clap(
            long,
            help = "Change reserve for RBF transactions",
            default_value = "5000"
        )]
        change_reserve: Option<u128>,
        #[clap(
            short,
            long,
            help = "Optional ZIP-302 memo for shielded Zcash recipients (only valid with --chain zcash)"
        )]
        memo: Option<String>,
    },

    /// Request the MPC signature for a pending UTXO withdrawal
    Sign {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Pending UTXO transaction ID")]
        pending_id: Option<String>,
        #[clap(
            long,
            help = "NEAR tx hash of the init transfer (alternative to --pending-id)"
        )]
        near_tx: Option<String>,
        #[clap(long, help = "Account that initialized the transfer")]
        user_account: Option<AccountId>,
        #[clap(
            long,
            help = "Index of the signature in the UTXO transaction",
            default_value = "0"
        )]
        sign_index: u64,
    },

    /// Broadcast a signed withdrawal to the UTXO chain
    Broadcast {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(long, help = "NEAR tx hash carrying the signature")]
        near_tx: String,
        #[clap(short, long, help = "Account that signed the transfer")]
        relayer: Option<AccountId>,
    },

    /// Verify a withdrawal is confirmed on the UTXO chain
    VerifyWithdraw {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "UTXO chain tx hash")]
        tx: String,
    },

    /// Bump the fee of an RBF withdrawal transaction
    BumpFee {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "UTXO chain tx hash")]
        tx: String,
        #[clap(short, long, help = "New fee rate on the UTXO chain")]
        fee_rate: Option<u64>,
    },

    /// Cancel a pending withdrawal
    CancelWithdraw {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "UTXO chain tx hash")]
        tx: String,
    },

    /// Rebalance connector UTXOs (active UTXO management)
    Rebalance {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Fee rate on the UTXO chain")]
        fee_rate: Option<u64>,
        #[clap(
            long,
            help = "Override the max number of UTXO inputs to consume (defaults to the bridge config value)"
        )]
        max_input_number: Option<u8>,
        #[clap(
            long,
            help = "Merge the largest UTXOs instead of the smallest (use ahead of a large withdrawal)"
        )]
        merge_largest: bool,
        #[clap(
            long,
            help = "Override the max change amount per output (defaults to the bridge config value)"
        )]
        max_change_amount: Option<u128>,
        #[clap(
            long,
            help = "Divisor applied to max_change_amount to cap individual UTXO size when merging largest (defaults to 2)"
        )]
        merge_cap_divisor: Option<u128>,
    },

    /// Verify a rebalancing tx is confirmed on the UTXO chain
    VerifyRebalance {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "UTXO chain tx hash")]
        tx: String,
    },

    /// Refund a never-finalized deposit back to its refund address
    #[command(subcommand)]
    Refund(RefundCmd),

    #[clap(hide = true, about = "Withdraw from NEAR to a UTXO chain address")]
    Withdraw {
        #[clap(short, long, value_enum, help = "UTXO chain")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Target BTC/ZEC address")]
        target_address: String,
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(
            short,
            long,
            help = "Optional ZIP-302 memo for shielded Zcash recipients (only valid with --chain zcash)"
        )]
        memo: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum RefundCmd {
    /// Request a refund for a never-finalized deposit
    Request {
        #[clap(short, long, value_enum, help = "UTXO chain the deposit was made on")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Deposit tx hash on the UTXO chain")]
        tx: String,
        #[clap(
            short,
            long,
            help = "Index of the deposit output. If omitted, auto-resolved (see `utxo finalize-deposit --help`)"
        )]
        vout: Option<usize>,
        #[clap(
            short,
            long,
            help = "Original deposit recipient: <chain>:<address> for an Omni-Bridge-routed deposit, a bare NEAR account for a direct deposit. If omitted, looked up from the bridge indexer"
        )]
        recipient: Option<BtcRecipient>,
        #[clap(
            short,
            long,
            help = "Omni Bridge fee in satoshi used at deposit time (ignored for direct NEAR deposits)",
            default_value = "0"
        )]
        fee: u128,
        #[clap(
            long,
            help = "UTXO address to send the refund to. Used only when the original DepositMsg does not carry a refund_address; if the deposit message has one, that value is used regardless"
        )]
        refund_address: Option<String>,
        #[clap(
            long,
            help = "Optional msg set as SafeDepositMsg.msg used at deposit time (only valid with a direct NEAR recipient)"
        )]
        msg: Option<String>,
        #[clap(
            long,
            help = "Set this if the original deposit's DepositMsg.refund_address was None. When set, --refund-address is used only as the refund destination and is NOT included in the deposit message used to recompute the on-chain UTXO",
            default_value_t = false
        )]
        no_deposit_refund_address: bool,
        #[clap(long, help = "Optional custom gas fee in satoshi (DAO/Operator only)")]
        gas_fee: Option<u128>,
        #[clap(
            long,
            help = "Derive the deposit address via the UTXO connector contract view method (true, default) or the bridge indexer service (false). Only used with --recipient; auto-discovery always asks the indexer",
            default_value_t = true,
            action = clap::ArgAction::Set
        )]
        from_contract: bool,
    },

    /// Execute a previously requested refund, sending the deposit back
    Execute {
        #[clap(short, long, value_enum, help = "UTXO chain the deposit was made on")]
        chain: UTXOChainArg,
        #[clap(
            long,
            help = "Refund request key in the form <tx_id>@<vout>. Mutually exclusive with --tx/--vout"
        )]
        key: Option<String>,
        #[clap(
            short,
            long,
            help = "Deposit tx hash; combined with --vout to form the refund request key"
        )]
        tx: Option<String>,
        #[clap(short, long, help = "Index of the deposit output")]
        vout: Option<usize>,
        #[clap(
            long,
            help = "Transparent refund: send the deposit back to a transparent address with no Orchard bundle. For Zcash this overrides the default of auto-generating a shielded Orchard bundle; on Bitcoin refunds are always transparent"
        )]
        transparent: bool,
    },

    /// Verify the refund tx is confirmed on the UTXO chain
    Verify {
        #[clap(short, long, value_enum, help = "UTXO chain the refund was made on")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Refund tx hash on the UTXO chain")]
        tx: String,
    },
}

/// User-supplied bundle that lets us reconstruct the original `DepositMsg`
/// locally instead of asking the bridge indexer. Pass `None` to
/// `resolve_btc_deposit` when the caller wants full auto-discovery.
struct ManualDepositInput {
    recipient: BtcRecipient,
    deposit_refund_address: Option<String>,
    fee: u128,
    safe_msg: Option<String>,
}

/// Resolve the `(BtcDepositArgs, vout, prefetched proof)` triple consumed by
/// the BTC fin-transfer and refund flows.
///
/// - When `manual` is `Some`, builds `BtcDepositArgs` from the supplied
///   recipient/fee/msg/refund and resolves `vout` either from the explicit
///   value or by matching it against the derived deposit address (from the
///   UTXO connector contract when `from_contract` is set, from the bridge
///   indexer otherwise).
/// - When `manual` is `None`, asks the bridge indexer (via
///   `resolve_deposit_from_tx`) which output is a tracked deposit address;
///   the recovered `DepositMsg` is wrapped as `BtcDepositArgs::DepositMsg`.
///
/// In both paths the returned `PrefetchedTxData` lets downstream calls skip a
/// redundant `extract_btc_proof` round-trip.
async fn resolve_btc_deposit(
    connector: &OmniConnector,
    chain: ChainKind,
    network: utxo_utils::address::Network,
    btc_tx_hash: &str,
    vout: Option<usize>,
    manual: Option<ManualDepositInput>,
    from_contract: bool,
) -> (BtcDepositArgs, usize, Option<PrefetchedTxData>) {
    match manual {
        Some(ManualDepositInput {
            recipient,
            deposit_refund_address,
            fee,
            safe_msg,
        }) => {
            let deposit_args = match recipient {
                BtcRecipient::Omni(recipient_id) => {
                    if safe_msg.is_some() {
                        die("--msg is not supported with a chain-prefixed recipient; use a direct NEAR account (e.g. 'foo.near') instead");
                    }
                    BtcDepositArgs::OmniDepositArgs {
                        recipient_id,
                        refund_address: deposit_refund_address,
                        fee,
                    }
                }
                BtcRecipient::Direct(account_id) => BtcDepositArgs::DepositMsg {
                    msg: DepositMsg {
                        recipient_id: account_id,
                        post_actions: None,
                        extra_msg: None,
                        safe_deposit: safe_msg.map(|msg| SafeDepositMsg { msg }),
                        refund_address: deposit_refund_address,
                    },
                },
            };
            let (v, p) = match vout {
                Some(v) => (v, None),
                None => {
                    let (v, p) = connector
                        .resolve_deposit_vout(
                            chain,
                            network,
                            btc_tx_hash,
                            &deposit_args,
                            from_contract,
                        )
                        .await
                        .unwrap();
                    (v, Some(p))
                }
            };
            (deposit_args, v, p)
        }
        None => {
            let (v, found_msg, p) = connector
                .resolve_deposit_from_tx(chain, network, btc_tx_hash, vout)
                .await
                .unwrap();
            (BtcDepositArgs::DepositMsg { msg: found_msg }, v, Some(p))
        }
    }
}

/// Fully automatic deposit finalization: deposit message, vout, and proof are
/// all discovered from the tx. Used by `transfer finalize --tx btc:<hash>`.
pub async fn finalize_deposit_auto(ctx: &Ctx, chain: ChainKind, tx_hash: &str) {
    let connector = ctx.connector();
    let (deposit_args, vout, prefetched) = resolve_btc_deposit(
        &connector,
        chain,
        ctx.network.into(),
        tx_hash,
        None,
        None,
        false,
    )
    .await;

    connector
        .near_fin_transfer_btc_checked(
            chain,
            tx_hash.to_string(),
            vout,
            deposit_args,
            prefetched,
            TransactionOptions::default(),
        )
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)]
pub async fn run(cmd: UtxoCmd, ctx: &Ctx) {
    match cmd {
        UtxoCmd::DepositAddress {
            chain,
            recipient,
            refund_address,
            fee,
            from_contract,
        } => {
            let btc_address = ctx
                .connector()
                .get_btc_address(chain.into(), &recipient, refund_address, fee, from_contract)
                .await
                .unwrap();

            tracing::info!("Deposit address: {btc_address}");
        }
        UtxoCmd::FinalizeDeposit {
            chain,
            tx,
            vout,
            recipient,
            refund_address,
            fee,
            msg,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            let connector = ctx.connector();

            let manual = match recipient {
                Some(recipient) => Some(ManualDepositInput {
                    recipient,
                    deposit_refund_address: refund_address,
                    fee,
                    safe_msg: msg,
                }),
                None => {
                    if refund_address.is_some() || fee != 0 || msg.is_some() {
                        die("--recipient is required when --refund-address, --fee, or --msg is supplied");
                    }
                    None
                }
            };

            let (deposit_args, resolved_vout, prefetched) = resolve_btc_deposit(
                &connector,
                chain.into(),
                ctx.network.into(),
                &tx,
                vout,
                manual,
                false,
            )
            .await;

            // `--dry-run` (if set) is honored at the NEAR client: the verify_deposit
            // transaction is printed as an unsigned payload instead of broadcast.
            // The `_checked` variant pre-checks light-client confirmations, giving
            // a clear error instead of a contract panic.
            connector
                .near_fin_transfer_btc_checked(
                    chain.into(),
                    tx,
                    resolved_vout,
                    deposit_args,
                    prefetched,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        UtxoCmd::FastFinalizeDeposit {
            chain,
            tx,
            recipient,
            refund_address,
            fee,
            storage_deposit_amount,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_fast_transfer_from_utxo(
                    chain.into(),
                    tx,
                    recipient,
                    refund_address,
                    fee,
                    storage_deposit_amount,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        UtxoCmd::SubmitTransfer {
            chain,
            near_tx,
            sender_id,
            fee_rate,
            change_reserve,
            memo,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_submit_btc_transfer_with_tx_hash(
                    chain.into(),
                    CryptoHash::from_str(&near_tx)
                        .unwrap_or_else(|e| die(format!("invalid NEAR tx hash: {e}"))),
                    sender_id,
                    fee_rate,
                    TransactionOptions::default(),
                    change_reserve,
                    memo,
                    None,
                )
                .await
                .unwrap();
        }
        UtxoCmd::Sign {
            chain,
            pending_id,
            near_tx,
            user_account,
            sign_index,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            if let Some(pending_id) = pending_id {
                ctx.connector()
                    .near_sign_btc_transaction(
                        chain.into(),
                        pending_id,
                        sign_index,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();
            } else {
                let near_tx =
                    near_tx.unwrap_or_else(|| die("pass either --pending-id or --near-tx"));
                ctx.connector()
                    .near_sign_btc_transaction_with_tx_hash(
                        chain.into(),
                        CryptoHash::from_str(&near_tx)
                            .unwrap_or_else(|e| die(format!("invalid NEAR tx hash: {e}"))),
                        user_account,
                        sign_index,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();
            }
        }
        UtxoCmd::Broadcast {
            chain,
            near_tx,
            relayer,
        } => {
            // Constructs the signed UTXO transaction and broadcasts it to the
            // UTXO network directly; there is no dry-run representation.
            ensure_dry_run_allowed(ctx, chain.into());
            let tx_hash = ctx
                .connector()
                .fin_transfer(FinTransferArgs::UTXOChainFinTransfer {
                    chain: chain.into(),
                    near_tx_hash: CryptoHash::from_str(&near_tx)
                        .unwrap_or_else(|e| die(format!("invalid NEAR tx hash: {e}"))),
                    relayer,
                })
                .await
                .unwrap();

            tracing::info!("UTXO chain tx hash: {tx_hash}");
        }
        UtxoCmd::VerifyWithdraw { chain, tx } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_btc_verify_withdraw(chain.into(), tx, TransactionOptions::default())
                .await
                .unwrap();
        }
        UtxoCmd::BumpFee {
            chain,
            tx,
            fee_rate,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_rbf_increase_gas_fee(
                    chain.into(),
                    tx,
                    fee_rate,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        UtxoCmd::CancelWithdraw { chain, tx } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_btc_cancel_withdraw(chain.into(), tx, TransactionOptions::default())
                .await
                .unwrap();
        }
        UtxoCmd::Rebalance {
            chain,
            fee_rate,
            max_input_number,
            merge_largest,
            max_change_amount,
            merge_cap_divisor,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .active_utxo_management(
                    chain.into(),
                    fee_rate,
                    max_input_number,
                    merge_largest,
                    max_change_amount,
                    merge_cap_divisor,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        UtxoCmd::VerifyRebalance { chain, tx } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .near_btc_verify_active_utxo_management(
                    chain.into(),
                    tx,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        UtxoCmd::Refund(cmd) => refund(cmd, ctx).await,
        UtxoCmd::Withdraw {
            chain,
            target_address,
            amount,
            memo,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            let tx_hash = ctx
                .connector()
                .init_near_to_bitcoin_transfer(
                    chain.into(),
                    target_address,
                    amount,
                    TransactionOptions::default(),
                    memo,
                )
                .await
                .unwrap();

            tracing::info!("NEAR tx hash: {tx_hash}");
        }
    }
}

async fn refund(cmd: RefundCmd, ctx: &Ctx) {
    match cmd {
        RefundCmd::Request {
            chain,
            tx,
            vout,
            recipient,
            fee,
            refund_address,
            msg,
            no_deposit_refund_address,
            gas_fee,
            from_contract,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            let chain_kind: ChainKind = chain.into();
            let connector = ctx.connector();

            let manual = match recipient {
                Some(recipient) => {
                    let deposit_refund_address = if no_deposit_refund_address {
                        None
                    } else {
                        refund_address.clone()
                    };
                    Some(ManualDepositInput {
                        recipient,
                        deposit_refund_address,
                        fee,
                        safe_msg: msg,
                    })
                }
                None => {
                    if fee != 0 || msg.is_some() || no_deposit_refund_address {
                        die("--recipient is required when --fee, --msg, or --no-deposit-refund-address is supplied");
                    }
                    None
                }
            };

            let (btc_deposit_args, resolved_vout, prefetched) = resolve_btc_deposit(
                &connector,
                chain_kind,
                ctx.network.into(),
                &tx,
                vout,
                manual,
                from_contract,
            )
            .await;

            let deposit_msg_refund_address = match &btc_deposit_args {
                BtcDepositArgs::DepositMsg { msg } => msg.refund_address.clone(),
                BtcDepositArgs::OmniDepositArgs { refund_address, .. }
                | BtcDepositArgs::NearDirectDepositArgs { refund_address, .. } => {
                    refund_address.clone()
                }
            };
            let final_refund_address = deposit_msg_refund_address
                .or(refund_address)
                .unwrap_or_else(|| {
                    die("No refund destination: pass --refund-address (the deposit message has no refund_address)")
                });

            // `--dry-run` (if set) is honored at the NEAR client: the request_refund
            // transaction is printed as an unsigned payload instead of broadcast.
            connector
                .btc_request_refund(
                    chain_kind,
                    tx,
                    resolved_vout,
                    btc_deposit_args,
                    final_refund_address,
                    gas_fee,
                    prefetched,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        RefundCmd::Execute {
            chain,
            key,
            tx,
            vout,
            transparent,
        } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            let chain_kind: ChainKind = chain.into();
            let utxo_storage_key = match key {
                Some(key) => key,
                None => {
                    let tx =
                        tx.unwrap_or_else(|| die("provide either --key or both --tx and --vout"));
                    let vout =
                        vout.unwrap_or_else(|| die("provide either --key or both --tx and --vout"));
                    format!("{tx}@{vout}")
                }
            };

            let connector = ctx.connector();

            let chain_specific_data = if transparent || chain_kind != ChainKind::Zcash {
                None
            } else {
                Some(
                    connector
                        .build_refund_chain_specific_data(&utxo_storage_key)
                        .await
                        .unwrap(),
                )
            };

            connector
                .btc_execute_refund(
                    chain_kind,
                    utxo_storage_key,
                    chain_specific_data,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        RefundCmd::Verify { chain, tx } => {
            ensure_dry_run_allowed(ctx, ChainKind::Near);
            ctx.connector()
                .btc_verify_refund_finalize(chain.into(), tx, TransactionOptions::default())
                .await
                .unwrap();
        }
    }
}
