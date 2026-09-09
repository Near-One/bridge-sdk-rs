use std::str::FromStr;

use alloy::primitives::TxHash;
use clap::Subcommand;
use near_bridge_client::TransactionOptions;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{BindTokenArgs, DeployTokenArgs};
use omni_types::{ChainKind, OmniAddress};

use crate::connector::ensure_dry_run_allowed;

use super::{die, ChainTx, Ctx};

#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    /// Log a token's metadata on its chain (first step of deploying it to
    /// other chains)
    LogMetadata {
        #[clap(short, long, help = "Token as <chain>:<address>")]
        token: OmniAddress,
    },

    /// Deploy a bridged token on a destination chain
    Deploy {
        #[clap(
            short,
            long,
            help = "Proof tx as <chain>:<hash>: the LogMetadata tx when deploying on NEAR, the NEAR log_metadata tx when deploying anywhere else"
        )]
        tx: ChainTx,
        #[clap(long, help = "Chain to deploy the token on")]
        on: ChainKind,
    },

    /// Bind a deployed token on NEAR (final step of deployment)
    Bind {
        #[clap(
            short,
            long,
            help = "deploy_token tx on the chain the token was deployed to, as <chain>:<hash>"
        )]
        tx: ChainTx,
    },

    /// Deposit NEP-141 storage for an account on NEAR
    StorageDeposit {
        #[clap(short, long, help = "Token account to deposit storage for")]
        token: AccountId,
        #[clap(
            short,
            long,
            help = "Amount in yoctoNEAR (defaults to the token's required storage deposit)"
        )]
        amount: Option<u128>,
        #[clap(
            long,
            help = "Account to deposit storage for (defaults to the NEAR signer)"
        )]
        account_id: Option<AccountId>,
    },
}

pub async fn run(cmd: TokenCmd, ctx: &Ctx) {
    match cmd {
        TokenCmd::LogMetadata { token } => {
            ensure_dry_run_allowed(ctx, token.get_chain());
            ctx.connector()
                .log_metadata(token, TransactionOptions::default())
                .await
                .unwrap();
        }
        TokenCmd::Deploy { tx, on } => deploy(ctx, tx, on).await,
        TokenCmd::Bind { tx } => bind(ctx, tx).await,
        TokenCmd::StorageDeposit {
            token,
            amount,
            account_id,
        } => storage_deposit(ctx, token, amount, account_id).await,
    }
}

async fn deploy(ctx: &Ctx, tx: ChainTx, on: ChainKind) {
    ensure_dry_run_allowed(ctx, on);
    let connector = ctx.connector();

    if on == ChainKind::Near {
        let args = match tx.chain {
            ChainKind::Eth => DeployTokenArgs::NearDeployTokenWithEvmProof {
                chain_kind: tx.chain,
                tx_hash: TxHash::from_str(&tx.hash)
                    .unwrap_or_else(|e| die(format!("invalid tx hash: {e}"))),
                transaction_options: TransactionOptions::default(),
            },
            ChainKind::Abs | ChainKind::Strk | ChainKind::Aptos => {
                DeployTokenArgs::NearDeployTokenWithMpcProof {
                    chain_kind: tx.chain,
                    tx_hash: tx.hash,
                    transaction_options: TransactionOptions::default(),
                }
            }
            ChainKind::Near | ChainKind::Btc | ChainKind::Zcash => die(format!(
                "cannot deploy on NEAR from a {:?} transaction; pass the LogMetadata tx of the token's origin chain",
                tx.chain
            )),
            _ => DeployTokenArgs::NearDeployToken {
                chain_kind: tx.chain,
                tx_hash: tx.hash,
                transaction_options: TransactionOptions::default(),
            },
        };
        connector.deploy_token(args).await.unwrap();
        return;
    }

    if tx.chain != ChainKind::Near {
        die(format!(
            "deploying on {on:?} takes the NEAR log_metadata transaction as proof; got a {:?} tx",
            tx.chain
        ));
    }
    let near_tx_hash = CryptoHash::from_str(&tx.hash)
        .unwrap_or_else(|e| die(format!("invalid NEAR tx hash: {e}")));

    let args = match on {
        ChainKind::Eth
        | ChainKind::Arb
        | ChainKind::Base
        | ChainKind::Bnb
        | ChainKind::Pol
        | ChainKind::HyperEvm
        | ChainKind::Abs => DeployTokenArgs::EvmDeployTokenWithTxHash {
            chain_kind: on,
            near_tx_hash,
            tx_nonce: None,
        },
        ChainKind::Sol | ChainKind::Fogo => DeployTokenArgs::SvmDeployTokenWithTxHash {
            chain_kind: on,
            near_tx_hash,
            sender_id: None,
        },
        ChainKind::Strk => DeployTokenArgs::StarknetDeployTokenWithTxHash {
            near_tx_hash,
            sender_id: None,
        },
        ChainKind::Aptos => DeployTokenArgs::AptosDeployTokenWithTxHash {
            near_tx_hash,
            sender_id: None,
        },
        ChainKind::Btc | ChainKind::Zcash => die("DeployToken is not supported for UTXO chains"),
        ChainKind::Near => unreachable!(),
    };
    connector.deploy_token(args).await.unwrap();
}

async fn bind(ctx: &Ctx, tx: ChainTx) {
    ensure_dry_run_allowed(ctx, ChainKind::Near);
    let args = match tx.chain {
        ChainKind::Eth => BindTokenArgs::BindTokenWithEvmProofTx {
            chain_kind: tx.chain,
            tx_hash: TxHash::from_str(&tx.hash)
                .unwrap_or_else(|e| die(format!("invalid tx hash: {e}"))),
            transaction_options: TransactionOptions::default(),
        },
        ChainKind::Abs | ChainKind::Strk | ChainKind::Aptos => {
            BindTokenArgs::BindTokenWithMpcProofTx {
                chain_kind: tx.chain,
                tx_hash: tx.hash,
                transaction_options: TransactionOptions::default(),
            }
        }
        ChainKind::Near | ChainKind::Btc | ChainKind::Zcash => die(format!(
            "cannot bind from a {:?} transaction; pass the deploy_token tx on the token's deployed chain",
            tx.chain
        )),
        _ => BindTokenArgs::BindTokenWithVaaProofTx {
            chain_kind: tx.chain,
            tx_hash: tx.hash,
            transaction_options: TransactionOptions::default(),
        },
    };
    ctx.connector().bind_token(args).await.unwrap();
}

async fn storage_deposit(
    ctx: &Ctx,
    token: AccountId,
    amount: Option<u128>,
    account_id: Option<AccountId>,
) {
    ensure_dry_run_allowed(ctx, ChainKind::Near);
    let connector = ctx.connector();

    let account_id = account_id.unwrap_or_else(|| {
        ctx.config
            .near_signer
            .as_deref()
            .unwrap_or_else(|| die("pass --account-id or configure the NEAR signer"))
            .parse()
            .unwrap_or_else(|e| die(format!("invalid NEAR signer account: {e}")))
    });

    let amount = match amount {
        Some(amount) => amount,
        None => {
            let required = connector
                .near_get_required_storage_deposit(token.clone(), account_id.clone())
                .await
                .unwrap_or_else(|e| die(format!("failed to fetch required storage deposit: {e}")));
            tracing::info!("Using required storage deposit: {required} yoctoNEAR");
            required
        }
    };

    connector
        .near_storage_deposit_for_token(token, amount, account_id, TransactionOptions::default())
        .await
        .unwrap();
}
