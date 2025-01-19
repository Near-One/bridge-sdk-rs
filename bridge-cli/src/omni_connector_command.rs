use std::{path::Path, str::FromStr};

use clap::Subcommand;

use ethers_core::types::TxHash;
use evm_bridge_client::EvmBridgeClientBuilder;
use near_bridge_client::NearBridgeClientBuilder;
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
        #[clap(short, long, help = "Token address to logging metadata")]
        token: OmniAddress,
        #[command(flatten)]
        config_cli: CliConfig,
    },

    #[clap(about = "Deploy a token on NEAR")]
    NearDeployToken {
        #[clap(short, long, help = "Chain to deploy the token on")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the LogMetadata call on other chain"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Deploy a token on NEAR with EVM proof")]
    NearDeployTokenWithEvmProof {
        #[clap(short, long, help = "Chain to deploy the token on")]
        chain: ChainKind,
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
        #[clap(short, long, help = "Origin chain ID of transfer to sign")]
        origin_chain_id: u8,
        #[clap(short, long, help = "Origin nonce of transfer to sign")]
        origin_nonce: u64,
        #[clap(short, long, help = "Fee recipient account ID")]
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
        #[clap(short, long, help = "Recipient account ID on the other chain")]
        receiver: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on NEAR")]
    NearFinTransfer {
        #[clap(short, long, help = "Chain to finalize the transfer on")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Storage deposit actions. Format: token_id1:account_id1:amount1,token_id2:account_id2:amount2,..."
        )]
        storage_deposit_actions: Vec<String>,
        #[clap(short, long, help = "VAA from init transfer transaction")]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Deploy a token on EVM")]
    EvmDeployToken {
        #[clap(short, long, help = "Chain to deploy the token on")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the LogMetadata call on other chain"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Bind a token on EVM")]
    EvmBindToken {
        #[clap(short, long, help = "Chain to bind the token on")]
        chain: ChainKind,
        #[clap(short, long, help = "VAA from DeployToken call")]
        tx_hash: String,
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
        #[clap(short, long, help = "Recipient address on the other chain")]
        receiver: String,
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: u128,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: u128,
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
        #[clap(short, long, help = "Keypair (private_key) for the program")]
        program_keypair: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Deploy a token on Solana")]
    SolanaDeployToken {
        #[clap(
            short,
            long,
            help = "Transaction hash of the LogMetadata call on other chain"
        )]
        tx_hash: String,
        #[clap(short, long, help = "Sender ID of the LogMetadata call on NEAR")]
        sender_id: Option<AccountId>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a transfer on Solana")]
    SolanaInitTransfer {
        #[clap(short, long, help = "Token to transfer")]
        token: String,
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient account ID on the other chain")]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a native transfer on Solana")]
    SolanaInitTransferSol {
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient account ID on the other chain")]
        recipient: String,
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

    #[clap(about = "Bind a token on a chain that supports Wormhole")]
    WormholeBindToken {
        #[clap(short, long, help = "Chain to bind the token on")]
        chain: ChainKind,
        #[clap(short, long, help = "VAA from deploy token transaction")]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: OmniConnectorSubCommand, network: Network) {
    match cmd {
        OmniConnectorSubCommand::LogMetadata { token, config_cli } => {
            omni_connector(network, config_cli)
                .log_metadata(token)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearDeployToken {
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::NearDeployToken {
                    chain_kind: chain,
                    tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
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
                    fee_recipient,
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
            chain,
            storage_deposit_actions,
            vaa,
            config_cli,
        } => {
            let args = omni_types::prover_args::WormholeVerifyProofArgs {
                proof_kind: omni_types::prover_result::ProofKind::InitTransfer,
                vaa,
            };
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::NearFinTransfer {
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
                    prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::EvmDeployToken {
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::EvmDeployTokenWithTxHash {
                    chain_kind: chain,
                    near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmBindToken {
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .bind_token(BindTokenArgs::EvmBindToken {
                    chain_kind: chain,
                    tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmInitTransfer {
            chain,
            token,
            amount,
            receiver,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::EvmInitTransfer {
                    chain_kind: chain,
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
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::EvmFinTransferWithTxHash {
                    near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    chain_kind: chain,
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::SolanaInitialize {
            program_keypair,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .solana_initialize(extract_solana_keypair(program_keypair))
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaDeployToken {
            tx_hash,
            sender_id,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::SolanaDeployTokenWithTxHash {
                    near_tx_hash: tx_hash.parse().unwrap(),
                    sender_id,
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

        OmniConnectorSubCommand::WormholeBindToken {
            chain,
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
                        chain_kind: chain,
                        prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                    },
                })
                .await
                .unwrap();
        }

        OmniConnectorSubCommand::NearDeployTokenWithEvmProof {
            chain,
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(DeployTokenArgs::NearDeployTokenWithEvmProof {
                    chain_kind: chain,
                    tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
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
        .keypair(combined_config.solana_keypair.map(extract_solana_keypair))
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

fn extract_solana_keypair(keypair: String) -> Keypair {
    if keypair.contains("/") || keypair.contains(".") {
        Keypair::read_from_file(Path::new(&keypair)).unwrap()
    } else {
        Keypair::from_base58_string(&keypair)
    }
}
