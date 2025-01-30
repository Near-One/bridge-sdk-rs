use crate::{combined_config, CliConfig, Network};
use clap::Subcommand;
use ethers_core::types::{Address, TxHash};
use legacy_eth_connector::{EthConnector, EthConnectorBuilder};
use near_primitives::hash::CryptoHash;
use std::str::FromStr;

#[derive(Subcommand, Debug)]
pub enum EthConnectorSubCommand {
    DepositToNear {
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient_account_id: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    DepositToEvm {
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient_address: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeDeposit {
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    WithdrawFromNear {
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient_address: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeWithdraw {
        #[clap(short, long)]
        reciept_id: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: EthConnectorSubCommand, network: Network) {
    match cmd {
        EthConnectorSubCommand::DepositToNear {
            amount,
            recipient_account_id,
            config_cli,
        } => {
            eth_connector(network, config_cli)
                .deposit_to_near(amount, recipient_account_id)
                .await
                .unwrap();
        }
        EthConnectorSubCommand::DepositToEvm {
            amount,
            recipient_address,
            config_cli,
        } => {
            eth_connector(network, config_cli)
                .deposit_to_evm(amount, recipient_address)
                .await
                .unwrap();
        }
        EthConnectorSubCommand::FinalizeDeposit {
            tx_hash,
            config_cli,
        } => {
            eth_connector(network, config_cli)
                .finalize_deposit(TxHash::from_str(&tx_hash).expect("Invalid tx_hash"))
                .await
                .unwrap();
        }
        EthConnectorSubCommand::WithdrawFromNear {
            amount,
            recipient_address,
            config_cli,
        } => {
            eth_connector(network, config_cli)
                .withdraw(
                    amount,
                    Address::from_str(&recipient_address).expect("Invalid recipient_address"),
                )
                .await
                .unwrap();
        }
        EthConnectorSubCommand::FinalizeWithdraw {
            reciept_id,
            config_cli,
        } => {
            eth_connector(network, config_cli)
                .finalize_withdraw(CryptoHash::from_str(&reciept_id).expect("Invalid receipt_id"))
                .await
                .unwrap();
        }
    }
}

fn eth_connector(network: Network, cli_config: CliConfig) -> EthConnector {
    let combined_config = combined_config(cli_config, network);

    EthConnectorBuilder::default()
        .eth_endpoint(combined_config.eth_rpc)
        .eth_chain_id(combined_config.eth_chain_id)
        .eth_private_key(combined_config.eth_private_key)
        .near_endpoint(combined_config.near_rpc)
        .near_signer(combined_config.near_signer)
        .near_private_key(combined_config.near_private_key)
        .eth_custodian_address(combined_config.eth_custodian_address)
        .eth_connector_account_id(combined_config.eth_connector_account_id)
        .near_light_client_address(combined_config.near_light_client_eth_address)
        .build()
        .unwrap()
}
