use std::str::FromStr;

use clap::Subcommand;

use ethers_core::types::TxHash;
use evm_bridge_client::EvmBridgeClientBuilder;
use near_bridge_client::NearBridgeClientBuilder;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{
    BindTokenArgs, DeployTokenArgs, FinTransferArgs, InitTransferArgs, LogMetadataArgs,
    OmniConnector, OmniConnectorBuilder,
};
use omni_types::{ChainKind, Fee, TransferId};
use solana_bridge_client::SolanaBridgeClientBuilder;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::signature::Keypair;

use crate::{combined_config, CliConfig, Network};

#[derive(Subcommand, Debug)]
pub enum OmniConnectorSubCommand {
    NearLogMetadata {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearDeployToken {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearStorageDeposit {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearSignTransfer {
        #[clap(short, long)]
        origin_chain_id: u8,
        #[clap(short, long)]
        origin_nonce: u64,
        #[clap(short, long)]
        fee_recipient: Option<String>,
        #[clap(short, long)]
        fee: u128,
        #[clap(long)]
        native_fee: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearInitTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        receiver: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearFinTransfer {
        #[clap(short, long)]
        token_id: String,
        #[clap(short, long)]
        account_id: String,
        #[clap(short, long)]
        storage_deposit_amount: Option<u128>,
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    EvmDeployToken {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmBindToken {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmInitTransfer {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        receiver: String,
        #[clap(short, long)]
        fee: u128,
        #[clap(short, long)]
        native_fee: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmFinTransfer {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    SolanaInitialize {
        #[clap(short, long)]
        program_keypair: Vec<u8>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaDeployToken {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaFinalizeTransfer {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[clap(short, long)]
        solana_token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaFinalizeTransferSol {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaLogMetadata {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaInitTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaInitTransferSol {
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    WormholeBindToken {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: OmniConnectorSubCommand, network: Network) {
    match cmd {
        OmniConnectorSubCommand::NearLogMetadata { token, config_cli } => {
            omni_connector(network, config_cli)
                .log_metadata(LogMetadataArgs::NearLogMetadata { token })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearDeployToken {
            source_chain_id,
            vaa,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::NearDeployToken {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    vaa,
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearStorageDeposit {
            token,
            amount,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_storage_deposit_for_token(token, amount)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearSignTransfer {
            origin_chain_id,
            origin_nonce,
            fee_recipient,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_sign_transfer(
                    TransferId {
                        origin_chain: ChainKind::try_from(origin_chain_id).unwrap(),
                        origin_nonce,
                    },
                    fee_recipient.map(|recipient| AccountId::from_str(&recipient).unwrap()),
                    Some(Fee {
                        fee: fee.into(),
                        native_fee: native_fee.into(),
                    }),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearInitTransfer {
            token,
            amount,
            receiver,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::NearInitTransfer {
                    token,
                    amount,
                    receiver,
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearFinTransfer {
            token_id,
            account_id,
            storage_deposit_amount,
            source_chain_id,
            vaa,
            config_cli,
        } => {
            let args = omni_types::prover_args::WormholeVerifyProofArgs {
                proof_kind: omni_types::prover_result::ProofKind::InitTransfer,
                vaa,
            };
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::NearFinTransfer {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    storage_deposit_actions: vec![omni_types::locker_args::StorageDepositAction {
                        token_id: AccountId::from_str(&token_id).unwrap(),
                        account_id: AccountId::from_str(&account_id).unwrap(),
                        storage_deposit_amount,
                    }],
                    prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::EvmDeployToken {
            source_chain_id,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::EvmDeployTokenWithTxHash {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmBindToken {
            source_chain_id,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .bind_token(BindTokenArgs::EvmBindToken {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmInitTransfer {
            source_chain_id,
            token,
            amount,
            receiver,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::EvmInitTransfer {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    token,
                    amount,
                    receiver,
                    fee: Fee {
                        fee: fee.into(),
                        native_fee: native_fee.into(),
                    },
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmFinTransfer {
            source_chain_id,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::EvmFinTransferWithTxHash {
                    near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::SolanaInitialize {
            program_keypair,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .solana_initialize(Keypair::from_bytes(&program_keypair).unwrap())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaLogMetadata { token, config_cli } => {
            omni_connector(network, config_cli)
                .log_metadata(LogMetadataArgs::SolanaLogMetadata {
                    token: token.parse().unwrap(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaDeployToken {
            transaction_hash,
            sender_id,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::SolanaDeployTokenWithTxHash {
                    near_tx_hash: transaction_hash.parse().unwrap(),
                    sender_id: sender_id.map(|id| id.parse().unwrap()),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaInitTransfer {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::SolanaInitTransfer {
                    token: token.parse().unwrap(),
                    amount,
                    recipient,
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaInitTransferSol {
            amount,
            recipient,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::SolanaInitTransferSol { amount, recipient })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaFinalizeTransfer {
            transaction_hash,
            sender_id,
            solana_token,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::SolanaFinTransferWithTxHash {
                    near_tx_hash: transaction_hash.parse().unwrap(),
                    solana_token: solana_token.parse().unwrap(),
                    sender_id: sender_id.map(|id| id.parse().unwrap()),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaFinalizeTransferSol { .. } => {}

        OmniConnectorSubCommand::WormholeBindToken {
            source_chain_id,
            vaa,
            config_cli,
        } => {
            let args = omni_types::prover_args::WormholeVerifyProofArgs {
                proof_kind: omni_types::prover_result::ProofKind::DeployToken,
                vaa,
            };
            omni_connector(network, config_cli)
                .bind_token(BindTokenArgs::WormholeBindToken {
                    bind_token_args: omni_types::locker_args::BindTokenArgs {
                        chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                        prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                    },
                })
                .await
                .unwrap();
        }
    }
}

fn omni_connector(network: Network, cli_config: CliConfig) -> OmniConnector {
    let combined_config = combined_config(cli_config, network);

    let near_bridge_client = NearBridgeClientBuilder::default()
        .endpoint(combined_config.near_rpc)
        .private_key(combined_config.near_private_key)
        .signer(combined_config.near_signer)
        .token_locker_id(combined_config.near_token_locker_id)
        .build()
        .unwrap();

    let eth_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.eth_rpc)
        .chain_id(combined_config.eth_chain_id)
        .private_key(combined_config.eth_private_key)
        .bridge_token_factory_address(combined_config.eth_bridge_token_factory_address)
        .build()
        .unwrap();

    let base_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.base_rpc)
        .chain_id(combined_config.base_chain_id)
        .private_key(combined_config.base_private_key)
        .bridge_token_factory_address(combined_config.base_bridge_token_factory_address)
        .build()
        .unwrap();

    let arb_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.arb_rpc)
        .chain_id(combined_config.arb_chain_id)
        .private_key(combined_config.arb_private_key)
        .bridge_token_factory_address(combined_config.arb_bridge_token_factory_address)
        .build()
        .unwrap();

    let solana_bridge_client = SolanaBridgeClientBuilder::default()
        .client(Some(RpcClient::new(combined_config.solana_rpc.unwrap())))
        .program_id(
            combined_config
                .solana_bridge_address
                .map(|addr| addr.parse().unwrap()),
        )
        .wormhole_core(
            combined_config
                .solana_wormhole_address
                .map(|addr| addr.parse().unwrap()),
        )
        .keypair(Some(Keypair::from_base58_string(
            &combined_config.solana_keypair.unwrap(),
        )))
        .build()
        .unwrap();

    OmniConnectorBuilder::default()
        .near_bridge_client(Some(near_bridge_client))
        .eth_bridge_client(Some(eth_bridge_client))
        .base_bridge_client(Some(base_bridge_client))
        .arb_bridge_client(Some(arb_bridge_client))
        .solana_bridge_client(Some(solana_bridge_client))
        .wormhole_bridge_client(None)
        .build()
        .unwrap()
}
