use clap::Subcommand;
use ethers_core::types::TxHash;
use nep141_connector::{Nep141Connector, Nep141ConnectorBuilder};
use std::str::FromStr;

use crate::{default_config, env_config, CliConfig, Network};

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
        #[clap(short, long)]
        log_index: u64,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: Nep141ConnectorSubCommand, network: Network) {
    match cmd {
        Nep141ConnectorSubCommand::LogMetadata { token, config_cli } => {
            let tx_hash = nep141_connector(network, config_cli)
                .log_token_metadata(token)
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::StorageDeposit {
            token,
            amount,
            config_cli,
        } => {
            let tx_hash = nep141_connector(network, config_cli)
                .storage_deposit_for_token(token, amount)
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::DeployToken {
            receipt_id,
            config_cli,
        } => {
            // TODO: use tx hash instead receipt_id
            let tx_hash = nep141_connector(network, config_cli)
                .deploy_token(receipt_id.parse().expect("Invalid receipt_id"))
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::Deposit {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            let tx_hash = nep141_connector(network, config_cli)
                .deposit(token, amount, recipient)
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::FinalizeDeposit {
            receipt_id,
            config_cli,
        } => {
            // TODO: use tx hash instead receipt_id
            let tx_hash = nep141_connector(network, config_cli)
                .mint(receipt_id.parse().expect("Invalid rreceipt_id"))
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::Withdraw {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            let tx_hash = nep141_connector(network, config_cli)
                .burn(token, amount, recipient)
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
        Nep141ConnectorSubCommand::FinalizeWithdraw {
            tx_hash,
            log_index,
            config_cli,
        } => {
            let tx_hash = nep141_connector(network, config_cli)
                .withdraw(
                    TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    log_index,
                )
                .await
                .unwrap();
            println!("Tx hash: {:#?}", tx_hash)
        }
    }
}

fn nep141_connector(network: Network, cli_config: CliConfig) -> Nep141Connector {
    // TODO: replace unwrap
    let combined_config = cli_config.or(env_config()).or(default_config(network));

    Nep141ConnectorBuilder::default()
        .eth_endpoint(combined_config.eth_rpc)
        .eth_chain_id(combined_config.eth_chain_id)
        .near_endpoint(combined_config.near_rpc)
        .token_locker_id(combined_config.token_locker_id)
        .bridge_token_factory_address(combined_config.bridge_token_factory_address)
        .near_light_client_address(combined_config.near_light_client_eth_address)
        .eth_private_key(combined_config.eth_private_key)
        .near_signer(combined_config.near_signer)
        .near_private_key(combined_config.near_private_key)
        .build()
        .unwrap()
}
