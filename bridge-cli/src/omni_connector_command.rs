use std::{path::Path, str::FromStr};

use clap::Subcommand;

use ethers_core::types::TxHash;
use evm_bridge_client::EvmBridgeClientBuilder;
use near_bridge_client::{NearBridgeClientBuilder, TransactionOptions};
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{
    BindTokenArgs, DeployTokenArgs, FinTransferArgs, InitTransferArgs, OmniConnector,
    OmniConnectorBuilder,
};
use omni_types::{ChainKind, Fee, OmniAddress, TransferId};
use solana_bridge_client::SolanaBridgeClientBuilder;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{signature::Keypair, signer::EncodableKey};
use wormhole_bridge_client::WormholeBridgeClientBuilder;

use crate::{combined_config, CliConfig, Network};

#[derive(Subcommand, Debug)]
pub enum OmniConnectorSubCommand {
    #[clap(about = "Log metadata for a token")]
    LogMetadata {
        #[clap(short, long, help = "Token address to log metadata")]
        token: OmniAddress,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    #[clap(about = "Deploy a token")]
    DeployToken {
        #[clap(short, long, help = "Origin chain of the token to deploy")]
        chain: ChainKind,
        #[clap(short, long, help = "The chain where the LogMetadata call was made")]
        source_chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the LogMetadata call on other chain"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Deposit storage for a token on NEAR")]
    NearStorageDeposit {
        #[clap(short, long, help = "Token to deposit storage for")]
        token: String,
        #[clap(short, long, help = "Amount to deposit")]
        amount: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Sign a transfer on NEAR")]
    NearSignTransfer {
        #[clap(long, help = "Origin chain ID of transfer to sign")]
        origin_chain_id: u8,
        #[clap(long, help = "Origin nonce of transfer to sign")]
        origin_nonce: u64,
        #[clap(long, help = "Fee recipient account ID")]
        fee_recipient: Option<AccountId>,
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: u128,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a transfer on NEAR")]
    NearInitTransfer {
        #[clap(short, long, help = "Token to transfer")]
        token: String,
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient address on the destination chain")]
        recipient: OmniAddress,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on NEAR using EVM proof")]
    NearFinTransferWithEvmProof {
        #[clap(short, long, help = "Origin chain of the transfer to finalize")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the InitTransfer call on other chain"
        )]
        tx_hash: String,
        #[clap(
            short,
            long,
            help = "Storage deposit actions. Format: token_id1:account_id1:amount1,token_id2:account_id2:amount2,..."
        )]
        storage_deposit_actions: Vec<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on NEAR using VAA")]
    NearFinTransferWithVaa {
        #[clap(short, long, help = "Origin chain of the transfer to finalize")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Storage deposit actions. Format: token_id1:account_id1:amount1,token_id2:account_id2:amount2,..."
        )]
        storage_deposit_actions: Vec<String>,
        #[clap(short, long, help = "VAA from InitTransfer call")]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a transfer on EVM")]
    EvmInitTransfer {
        #[clap(short, long, help = "Chain to initialize the transfer on")]
        chain: ChainKind,
        #[clap(short, long, help = "Token to transfer")]
        token: String,
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient address")]
        recipient: OmniAddress,
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: u128,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: u128,
        #[clap(short, long, help = "Additional message")]
        message: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on EVM")]
    EvmFinTransfer {
        #[clap(short, long, help = "Chain to finalize the transfer on")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the sign_transfer call on NEAR"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    #[clap(about = "Initialize a transfer on Solana")]
    SolanaInitialize {
        #[clap(
            short,
            long,
            help = "Solana keypair in Base58 or path to a .json keypair file"
        )]
        program_keypair: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a transfer on Solana")]
    SolanaInitTransfer {
        #[clap(short, long, help = "Token to transfer")]
        token: String,
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient address on the destination chain")]
        recipient: OmniAddress,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a native transfer on Solana")]
    SolanaInitTransferSol {
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient address on the destination chain")]
        recipient: OmniAddress,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on Solana")]
    SolanaFinalizeTransfer {
        #[clap(short, long, help = "Transaction hash of sign_transfer call on NEAR")]
        tx_hash: String,
        #[clap(long, help = "Sender ID of the sign_transfer call on NEAR")]
        sender_id: Option<AccountId>,
        #[clap(short, long, help = "Token to finalize the transfer for")]
        solana_token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a native transfer on Solana")]
    SolanaFinalizeTransferSol {
        #[clap(short, long, help = "Transaction hash of sign_transfer call on NEAR")]
        tx_hash: String,
        #[clap(short, long, help = "Sender ID of the sign_transfer call on NEAR")]
        sender_id: Option<AccountId>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaSetAdmin {
        #[clap(short, long, help = "Admin pubkey")]
        admin: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SolanaPause {
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Bind a token on a chain that supports Wormhole")]
    BindToken {
        #[clap(short, long, help = "Chain to bind the token from")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of deploy_token on the destination chain"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

#[allow(clippy::too_many_lines)]
pub async fn match_subcommand(cmd: OmniConnectorSubCommand, network: Network) {
    match cmd {
        OmniConnectorSubCommand::LogMetadata { token, config_cli } => {
            omni_connector(network, config_cli)
                .log_metadata(token, TransactionOptions::default())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::DeployToken {
            chain,
            source_chain,
            tx_hash,
            config_cli,
        } => match chain {
            ChainKind::Near => match source_chain {
                ChainKind::Eth => {
                    omni_connector(network, config_cli)
                        .deploy_token(DeployTokenArgs::NearDeployTokenWithEvmProof {
                            chain_kind: source_chain,
                            tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                _ => {
                    omni_connector(network, config_cli)
                        .deploy_token(DeployTokenArgs::NearDeployToken {
                            chain_kind: source_chain,
                            tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
            },
            ChainKind::Eth | ChainKind::Arb | ChainKind::Base => {
                omni_connector(network, config_cli)
                    .deploy_token(DeployTokenArgs::EvmDeployTokenWithTxHash {
                        chain_kind: chain,
                        near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                        tx_nonce: None,
                    })
                    .await
                    .unwrap();
            }
            ChainKind::Sol => {
                omni_connector(network, config_cli)
                    .deploy_token(DeployTokenArgs::SolanaDeployTokenWithTxHash {
                        near_tx_hash: tx_hash.parse().unwrap(),
                        sender_id: None,
                    })
                    .await
                    .unwrap();
            }
        },
        OmniConnectorSubCommand::NearStorageDeposit {
            token,
            amount,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_storage_deposit_for_token(token, amount, TransactionOptions::default())
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
        OmniConnectorSubCommand::NearInitTransfer {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::NearInitTransfer {
                    token,
                    amount,
                    recipient,
                    transaction_options: TransactionOptions::default(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearFinTransferWithEvmProof {
            chain,
            tx_hash,
            storage_deposit_actions,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::NearFinTransferWithEvmProof {
                    chain_kind: chain,
                    tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    storage_deposit_actions: storage_deposit_actions
                        .iter()
                        .map(|action| {
                            let parts: Vec<&str> = action.split(':').collect();
                            omni_types::locker_args::StorageDepositAction {
                                token_id: parts[0].parse().unwrap(),
                                account_id: parts[1].parse().unwrap(),
                                storage_deposit_amount: parts[2].parse().ok(),
                            }
                        })
                        .collect(),
                    transaction_options: TransactionOptions::default(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearFinTransferWithVaa {
            chain,
            storage_deposit_actions,
            vaa,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::NearFinTransferWithVaa {
                    chain_kind: chain,
                    storage_deposit_actions: storage_deposit_actions
                        .iter()
                        .map(|action| {
                            let parts: Vec<&str> = action.split(':').collect();
                            omni_types::locker_args::StorageDepositAction {
                                token_id: parts[0].parse().unwrap(),
                                account_id: parts[1].parse().unwrap(),
                                storage_deposit_amount: parts[2].parse().ok(),
                            }
                        })
                        .collect(),
                    vaa,
                    transaction_options: TransactionOptions::default(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmInitTransfer {
            chain,
            token,
            amount,
            recipient,
            fee,
            native_fee,
            message,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::EvmInitTransfer {
                    chain_kind: chain,
                    token,
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
        OmniConnectorSubCommand::EvmFinTransfer {
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::EvmFinTransferWithTxHash {
                    near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    chain_kind: chain,
                    tx_nonce: None,
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::SolanaInitialize {
            program_keypair,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .solana_initialize(extract_solana_keypair(&program_keypair))
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
                    message: String::new(),
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
                .init_transfer(InitTransferArgs::SolanaInitTransferSol {
                    amount,
                    recipient,
                    message: String::new(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaFinalizeTransfer {
            tx_hash,
            sender_id,
            solana_token,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::SolanaFinTransferWithTxHash {
                    near_tx_hash: tx_hash.parse().unwrap(),
                    solana_token: solana_token.parse().unwrap(),
                    sender_id,
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaFinalizeTransferSol { .. } => {}

        OmniConnectorSubCommand::BindToken {
            chain,
            tx_hash,
            config_cli,
        } => match chain {
            ChainKind::Eth => {
                omni_connector(network, config_cli)
                    .bind_token(BindTokenArgs::BindTokenWithEvmProofTx {
                        chain_kind: chain,
                        tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                        transaction_options: TransactionOptions::default(),
                    })
                    .await
                    .unwrap();
            }
            _ => {
                omni_connector(network, config_cli)
                    .bind_token(BindTokenArgs::BindTokenWithVaaProofTx {
                        chain_kind: chain,
                        tx_hash,
                        transaction_options: TransactionOptions::default(),
                    })
                    .await
                    .unwrap();
            }
        },
        OmniConnectorSubCommand::SolanaSetAdmin { admin, config_cli } => {
            omni_connector(network, config_cli)
                .solana_set_admin(admin.parse().unwrap())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaPause { config_cli } => {
            omni_connector(network, config_cli)
                .solana_pause()
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
        .keypair(
            combined_config
                .solana_keypair
                .as_deref()
                .map(extract_solana_keypair),
        )
        .build()
        .unwrap();

    let wormhole_bridge_client = WormholeBridgeClientBuilder::default()
        .endpoint(combined_config.wormhole_api)
        .build()
        .unwrap();

    OmniConnectorBuilder::default()
        .near_bridge_client(Some(near_bridge_client))
        .eth_bridge_client(Some(eth_bridge_client))
        .base_bridge_client(Some(base_bridge_client))
        .arb_bridge_client(Some(arb_bridge_client))
        .solana_bridge_client(Some(solana_bridge_client))
        .wormhole_bridge_client(Some(wormhole_bridge_client))
        .build()
        .unwrap()
}

fn extract_solana_keypair(keypair: &str) -> Keypair {
    if keypair.contains('/') || keypair.contains('.') {
        Keypair::read_from_file(Path::new(&keypair)).unwrap()
    } else {
        Keypair::from_base58_string(keypair)
    }
}
