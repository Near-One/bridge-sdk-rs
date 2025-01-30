use crate::{combined_config, CliConfig, Network};
use clap::Subcommand;
use ethers_core::types::TxHash;
use legacy_nep141_connector::{Nep141Connector, Nep141ConnectorBuilder};
use std::str::FromStr;

#[derive(Subcommand, Debug)]
pub enum Nep141ConnectorSubCommand {
    LogMetadata {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    StorageDeposit {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    DeployToken {
        #[clap(short, long)]
        receipt_id: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    Deposit {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeDeposit {
        #[clap(short, long)]
        receipt_id: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    Withdraw {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeWithdraw {
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: Nep141ConnectorSubCommand, network: Network) {
    match cmd {
        Nep141ConnectorSubCommand::LogMetadata { token, config_cli } => {
            nep141_connector(network, config_cli)
                .log_token_metadata(token)
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::StorageDeposit {
            token,
            amount,
            config_cli,
        } => {
            nep141_connector(network, config_cli)
                .storage_deposit_for_token(token, amount)
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::DeployToken {
            receipt_id,
            config_cli,
        } => {
            // TODO: use tx hash instead receipt_id
            nep141_connector(network, config_cli)
                .deploy_token(receipt_id.parse().expect("Invalid receipt_id"))
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::Deposit {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            nep141_connector(network, config_cli)
                .deposit(token, amount, recipient)
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::FinalizeDeposit {
            receipt_id,
            config_cli,
        } => {
            // TODO: use tx hash instead receipt_id
            nep141_connector(network, config_cli)
                .finalize_deposit(receipt_id.parse().expect("Invalid rreceipt_id"))
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::Withdraw {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            nep141_connector(network, config_cli)
                .withdraw(token, amount, recipient)
                .await
                .unwrap();
        }
        Nep141ConnectorSubCommand::FinalizeWithdraw {
            tx_hash,
            config_cli,
        } => {
            nep141_connector(network, config_cli)
                .finalize_withdraw(TxHash::from_str(&tx_hash).expect("Invalid tx_hash"))
                .await
                .unwrap();
        }
    }
}

fn nep141_connector(network: Network, cli_config: CliConfig) -> Nep141Connector {
    let combined_config = combined_config(cli_config, network);

    Nep141ConnectorBuilder::default()
        .eth_endpoint(combined_config.eth_rpc)
        .eth_chain_id(combined_config.eth_chain_id)
        .eth_private_key(combined_config.eth_private_key)
        .eth_bridge_token_factory_address(combined_config.eth_bridge_token_factory_address)
        .near_endpoint(combined_config.near_rpc)
        .near_token_locker_id(combined_config.near_token_locker_id)
        .near_light_client_address(combined_config.near_light_client_eth_address)
        .near_signer(combined_config.near_signer)
        .near_private_key(combined_config.near_private_key)
        .build()
        .unwrap()
}
