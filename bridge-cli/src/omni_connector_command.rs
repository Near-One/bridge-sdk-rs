use clap::Subcommand;
use core::panic;
use near_bridge_client::btc::SafeDepositMsg;
use std::collections::HashMap;
use std::{path::Path, str::FromStr};

use ethers_core::types::TxHash;
use evm_bridge_client::EvmBridgeClientBuilder;
use light_client::LightClientBuilder;
use near_bridge_client::{NearBridgeClientBuilder, TransactionOptions, UTXOChainAccounts};
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_connector::{
    BindTokenArgs, BtcDepositArgs, DeployTokenArgs, FinTransferArgs, InitTransferArgs,
    OmniConnector, OmniConnectorBuilder,
};
use omni_types::{ChainKind, Fee, OmniAddress, TransferId};
use solana_bridge_client::SolanaBridgeClientBuilder;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{signature::Keypair, signer::EncodableKey};
use utxo_bridge_client::{types::Bitcoin, types::Zcash, AuthOptions, UTXOBridgeClient};
use wormhole_bridge_client::WormholeBridgeClientBuilder;

use crate::{combined_config, CliConfig, Network};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
#[clap(name = "chain")]
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

impl From<Network> for utxo_utils::address::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => utxo_utils::address::Network::Mainnet,
            Network::Testnet | Network::Devnet => utxo_utils::address::Network::Testnet,
        }
    }
}

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

    #[clap(about = "Check if transfer is finalised")]
    IsTransferFinalised {
        #[clap(
            short,
            long,
            help = "Origin chain of the transfer is needed to check if transfer was finalized on NEAR"
        )]
        origin_chain: Option<ChainKind>,
        #[clap(short, long, help = "Destination chain of the transfer")]
        destination_chain: ChainKind,
        #[clap(short, long, help = "Destination nonce of the transfer")]
        nonce: u64,
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
        origin_chain: ChainKind,
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
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: Option<u128>,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: Option<u128>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on NEAR")]
    NearFinTransfer {
        #[clap(short, long, help = "Origin chain of the transfer to finalize")]
        chain: ChainKind,
        #[clap(short, long, help = "Destination chain of the transfer")]
        destination_chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the InitTransfer call on other chain"
        )]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize a transfer on NEAR using fast transfer")]
    NearFastFinTransfer {
        #[clap(short, long, help = "Origin chain of the transfer")]
        chain: ChainKind,
        #[clap(
            short,
            long,
            help = "Transaction hash of the init transfer call on origin chain"
        )]
        tx_hash: String,
        #[clap(long, help = "Storage deposit amount for tokens receiver")]
        storage_deposit_amount: Option<u128>,
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
    #[clap(about = "Get version of Solana OmniBridge program")]
    SolanaGetVersion {
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
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: u128,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: u64,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Initialize a native transfer on Solana")]
    SolanaInitTransferSol {
        #[clap(short, long, help = "Amount to transfer")]
        amount: u128,
        #[clap(short, long, help = "Recipient address on the destination chain")]
        recipient: OmniAddress,
        #[clap(short, long, help = "Fee to charge for the transfer")]
        fee: u128,
        #[clap(short, long, help = "Native fee to charge for the transfer")]
        native_fee: u64,
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
    SolanaUpdateMetadata {
        #[clap(short, long, help = "Token to update the metadata for")]
        token: String,
        #[clap(short, long, help = "URI to update the metadata to")]
        uri: Option<String>,
        #[clap(short, long, help = "Name to update the metadata to")]
        name: Option<String>,
        #[clap(short, long, help = "Symbol to update the metadata to")]
        symbol: Option<String>,
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
    #[clap(about = "Sign BTC transaction on Near")]
    NearSignBTCTransaction {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Pending BTC transaction ID")]
        btc_pending_id: Option<String>,
        #[clap(long, help = "Near tx Id of init transfer")]
        near_tx_hash: Option<String>,
        #[clap(long, help = "User Account ID who init the transfer")]
        user_account: Option<AccountId>,
        #[clap(
            short,
            long,
            help = "Index of the signature in the BTC transaction",
            default_value = "0"
        )]
        sign_index: u64,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Submit BTC transfer on Near")]
    NearSubmitBtcTransfer {
        #[clap(short, long, help = "UTXO Chain (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Omni Bridge Transaction Hash")]
        near_tx_hash: String,
        #[clap(short, long, help = "Sender ID who init transfer on Near")]
        sender_id: Option<AccountId>,
        #[clap(short, long, help = "Fee rate on UTXO chain")]
        fee_rate: Option<u64>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize Transfer from Bitcoin on Near")]
    NearFinTransferBTC {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Bitcoin tx hash")]
        btc_tx_hash: String,
        #[clap(
            short,
            long,
            help = "The index of the output in the Bitcoin transaction",
            default_value = "0"
        )]
        vout: usize,
        #[clap(short, long, help = "The BTC recipient on NEAR")]
        recipient_id: OmniAddress,
        #[clap(
            short,
            long,
            help = "The amount to be transferred, in satoshis",
            default_value = "0"
        )]
        amount: u128,
        #[clap(
            short,
            long,
            help = "The Omni Bridge Fee in satoshi",
            default_value = "0"
        )]
        fee: u128,
        #[clap(
            short,
            long,
            help = "Safe deposit message to perform `safe_verify_deposit` call"
        )]
        safe_deposit_msg: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Verify BTC Withdraw in btc_connector")]
    BtcVerifyWithdraw {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Bitcoin tx hash")]
        btc_tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Increase Gas Fee for RBF transaction in btc_connector")]
    BtcRBFIncreaseGasFee {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Bitcoin tx hash")]
        btc_tx_hash: String,
        #[clap(short, long, help = "Fee rate on UTXO chain")]
        fee_rate: Option<u64>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Cancel BTC Withdraw in btc_connector")]
    BtcCancelWithdraw {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Bitcoin tx hash")]
        btc_tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Verify Active UTXO Management in btc_connector")]
    BtcVerifyActiveUtxoManagement {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Bitcoin/ZCash tx hash")]
        btc_tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Finalize Transfer from Near on Bitcoin")]
    BtcFinTransfer {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(short, long, help = "Near tx hash with signature")]
        near_tx_hash: String,
        #[clap(short, long, help = "Account which Sign Transfer")]
        relayer: Option<AccountId>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(
        about = "Requests a Bitcoin address for transferring the specified amount to the given recipient on the Bitcoin network"
    )]
    GetBitcoinAddress {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[clap(
            short,
            long,
            help = "Transfer recipient in format <chain_id>:<address>"
        )]
        recipient_id: OmniAddress,
        #[clap(short, long, help = "The amount to be transferred, in satoshis")]
        amount: u128,
        #[clap(
            short,
            long,
            help = "The Omni Bridge Fee in satoshi",
            default_value = "0"
        )]
        fee: u128,
        #[clap(
            short,
            long,
            help = "Safe deposit message to perform `safe_verify_deposit` call"
        )]
        safe_deposit_msg: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Perform UTXO rebalancing for UTXO Chain Connector")]
    ActiveUTXOManagement {
        #[clap(short, long, help = "Chain for the UTXO rebalancing (Bitcoin/Zcash)")]
        chain: UTXOChainArg,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    #[clap(about = "Commands for internal usage, not recommended for the public")]
    Internal {
        #[command(subcommand)]
        subcommand: InternalSubCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum InternalSubCommand {
    #[clap(about = "Initiate a NEAR-to-Bitcoin transfer")]
    InitNearToBitcoinTransfer {
        #[clap(short, long, help = "Chain to transfer to")]
        chain: UTXOChainArg,
        #[clap(
            short,
            long,
            help = "The UTXO chain address to which the tokens will eventually be released"
        )]
        target_btc_address: String,
        #[clap(short, long, help = "The amount to be transferred, in satoshis")]
        amount: u128,
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
                            tx_hash,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
            },
            ChainKind::Eth | ChainKind::Arb | ChainKind::Base | ChainKind::Bnb => {
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
            ChainKind::Zcash | ChainKind::Btc => {
                panic!("DeployToken is not supported for UTXO chains");
            }
        },
        OmniConnectorSubCommand::IsTransferFinalised {
            origin_chain,
            destination_chain,
            nonce,
            config_cli,
        } => {
            let is_transfer_finalised = omni_connector(network, config_cli)
                .is_transfer_finalised(origin_chain, destination_chain, nonce)
                .await
                .unwrap();

            tracing::info!("Is transfer finalised: {}", is_transfer_finalised);
        }
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
            origin_chain,
            origin_nonce,
            fee_recipient,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_sign_transfer(
                    TransferId {
                        origin_chain,
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
        OmniConnectorSubCommand::NearSubmitBtcTransfer {
            chain,
            near_tx_hash,
            sender_id,
            fee_rate,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_submit_btc_transfer_with_tx_hash(
                    chain.into(),
                    CryptoHash::from_str(&near_tx_hash).expect("Invalid near_tx_hash"),
                    sender_id,
                    fee_rate,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearInitTransfer {
            token,
            amount,
            recipient,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::NearInitTransfer {
                    token,
                    amount,
                    recipient,
                    fee: fee.unwrap_or(0),
                    native_fee: native_fee.unwrap_or(0),
                    transaction_options: TransactionOptions::default(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearFinTransfer {
            chain,
            destination_chain,
            tx_hash,
            config_cli,
        } => {
            let connector = omni_connector(network, config_cli);

            let storage_deposit_actions = connector
                .get_storage_deposit_actions_for_tx(chain, tx_hash.clone())
                .await
                .unwrap();

            match chain {
                ChainKind::Eth => {
                    connector
                        .fin_transfer(FinTransferArgs::NearFinTransferWithEvmProof {
                            chain_kind: chain,
                            destination_chain,
                            tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                            storage_deposit_actions,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                ChainKind::Arb | ChainKind::Base | ChainKind::Bnb | ChainKind::Sol => {
                    let vaa = connector
                        .wormhole_get_vaa_by_tx_hash(tx_hash.clone())
                        .await
                        .unwrap();

                    connector
                        .fin_transfer(FinTransferArgs::NearFinTransferWithVaa {
                            chain_kind: chain,
                            destination_chain,
                            storage_deposit_actions,
                            vaa,
                            transaction_options: TransactionOptions::default(),
                        })
                        .await
                        .unwrap();
                }
                ChainKind::Near | ChainKind::Btc | ChainKind::Zcash => {
                    panic!("Unsupported chain for NearFinTransfer: {chain:?}");
                }
            }
        }
        OmniConnectorSubCommand::NearFastFinTransfer {
            chain,
            tx_hash,
            storage_deposit_amount,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_fast_transfer(
                    chain,
                    tx_hash,
                    storage_deposit_amount,
                    TransactionOptions::default(),
                )
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
        OmniConnectorSubCommand::SolanaGetVersion { config_cli } => {
            omni_connector(network, config_cli)
                .solana_get_version()
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaInitTransfer {
            token,
            amount,
            recipient,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::SolanaInitTransfer {
                    token: token.parse().unwrap(),
                    amount,
                    recipient,
                    fee,
                    native_fee,
                    message: String::new(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SolanaInitTransferSol {
            amount,
            recipient,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(InitTransferArgs::SolanaInitTransferSol {
                    amount,
                    recipient,
                    fee,
                    native_fee,
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
        OmniConnectorSubCommand::SolanaUpdateMetadata {
            token,
            uri,
            config_cli,
            name,
            symbol,
        } => {
            omni_connector(network, config_cli)
                .solana_update_metadata(token.parse().unwrap(), name, symbol, uri)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearSignBTCTransaction {
            chain,
            btc_pending_id,
            near_tx_hash,
            user_account,
            sign_index,
            config_cli,
        } => {
            if let Some(btc_pending_id) = btc_pending_id {
                omni_connector(network, config_cli)
                    .near_sign_btc_transaction(
                        chain.into(),
                        btc_pending_id,
                        sign_index,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();
            } else {
                omni_connector(network, config_cli)
                    .near_sign_btc_transaction_with_tx_hash(
                        chain.into(),
                        CryptoHash::from_str(&near_tx_hash.expect("near_tx_hash is required"))
                            .expect("Invalid near_tx_hash"),
                        user_account,
                        sign_index,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();
            }
        }
        OmniConnectorSubCommand::NearFinTransferBTC {
            chain,
            btc_tx_hash,
            vout,
            recipient_id,
            amount,
            fee,
            safe_deposit_msg,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_fin_transfer_btc(
                    chain.into(),
                    btc_tx_hash,
                    vout,
                    BtcDepositArgs::OmniDepositArgs {
                        recipient_id,
                        amount,
                        fee,
                        safe_deposit: safe_deposit_msg.map(|msg| SafeDepositMsg { msg }),
                    },
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BtcVerifyWithdraw {
            chain,
            btc_tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_btc_verify_withdraw(chain.into(), btc_tx_hash, TransactionOptions::default())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BtcRBFIncreaseGasFee {
            chain,
            btc_tx_hash,
            fee_rate,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_rbf_increase_gas_fee(
                    chain.into(),
                    btc_tx_hash,
                    fee_rate,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BtcCancelWithdraw {
            chain,
            btc_tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_btc_cancel_withdraw(chain.into(), btc_tx_hash, TransactionOptions::default())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BtcVerifyActiveUtxoManagement {
            chain,
            btc_tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_btc_verify_active_utxo_management(
                    chain.into(),
                    btc_tx_hash,
                    TransactionOptions::default(),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BtcFinTransfer {
            chain,
            near_tx_hash,
            relayer,
            config_cli,
        } => {
            let tx_hash = omni_connector(network, config_cli)
                .fin_transfer(FinTransferArgs::UTXOChainFinTransfer {
                    chain: chain.into(),
                    near_tx_hash: CryptoHash::from_str(&near_tx_hash)
                        .expect("Invalid near_tx_hash"),
                    relayer,
                })
                .await
                .unwrap();

            tracing::info!("BTC Tx Hash: {tx_hash}");
        }
        OmniConnectorSubCommand::GetBitcoinAddress {
            chain,
            recipient_id,
            amount,
            fee,
            safe_deposit_msg,
            config_cli,
        } => {
            let omni_connector = omni_connector(network, config_cli);
            let btc_address = omni_connector
                .get_btc_address(
                    chain.into(),
                    recipient_id,
                    amount,
                    fee,
                    safe_deposit_msg.map(|msg| SafeDepositMsg { msg }),
                )
                .await
                .unwrap();

            let transfer_amount = omni_connector
                .get_amount_to_transfer(chain.into(), amount)
                .await
                .unwrap();
            tracing::info!("BTC Address: {btc_address}");
            tracing::info!("Amount you need to transfer, including the fee: {transfer_amount}");
        }
        OmniConnectorSubCommand::ActiveUTXOManagement { chain, config_cli } => {
            omni_connector(network, config_cli)
                .active_utxo_management(chain.into(), TransactionOptions::default())
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::Internal { subcommand } => match subcommand {
            InternalSubCommand::InitNearToBitcoinTransfer {
                chain,
                target_btc_address,
                amount,
                config_cli,
            } => {
                let tx_hash = omni_connector(network, config_cli)
                    .init_near_to_bitcoin_transfer(
                        chain.into(),
                        target_btc_address,
                        amount,
                        TransactionOptions::default(),
                    )
                    .await
                    .unwrap();

                tracing::info!("Near Tx Hash: {tx_hash}");
            }
        },
    }
}

#[allow(clippy::too_many_lines)]
fn omni_connector(network: Network, cli_config: CliConfig) -> OmniConnector {
    let combined_config = combined_config(cli_config, network);

    let utxo_bridges = HashMap::from([
        (
            ChainKind::Zcash,
            UTXOChainAccounts {
                utxo_chain_connector: combined_config.zcash_connector,
                utxo_chain_token: combined_config.zcash,
                satoshi_relayer: None,
            },
        ),
        (
            ChainKind::Btc,
            UTXOChainAccounts {
                utxo_chain_connector: combined_config.btc_connector,
                utxo_chain_token: combined_config.btc,
                satoshi_relayer: combined_config.satoshi_relayer,
            },
        ),
    ]);

    let near_bridge_client = NearBridgeClientBuilder::default()
        .endpoint(combined_config.near_rpc.clone())
        .private_key(combined_config.near_private_key)
        .signer(combined_config.near_signer)
        .omni_bridge_id(combined_config.near_token_locker_id)
        .utxo_bridges(utxo_bridges)
        .build()
        .unwrap();

    let eth_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.eth_rpc)
        .chain_id(combined_config.eth_chain_id)
        .private_key(combined_config.eth_private_key)
        .omni_bridge_address(combined_config.eth_bridge_token_factory_address)
        .wormhole_core_address(None)
        .build()
        .unwrap();

    let base_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.base_rpc)
        .chain_id(combined_config.base_chain_id)
        .private_key(combined_config.base_private_key)
        .omni_bridge_address(combined_config.base_bridge_token_factory_address)
        .wormhole_core_address(combined_config.base_wormhole_address)
        .build()
        .unwrap();

    let arb_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.arb_rpc)
        .chain_id(combined_config.arb_chain_id)
        .private_key(combined_config.arb_private_key)
        .omni_bridge_address(combined_config.arb_bridge_token_factory_address)
        .wormhole_core_address(combined_config.arb_wormhole_address)
        .build()
        .unwrap();

    let bnb_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(combined_config.bnb_rpc)
        .chain_id(combined_config.bnb_chain_id)
        .private_key(combined_config.bnb_private_key)
        .omni_bridge_address(combined_config.bnb_bridge_token_factory_address)
        .wormhole_core_address(combined_config.bnb_wormhole_address)
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
        .wormhole_post_message_shim_program_id(
            combined_config
                .solana_wormhole_post_message_shim_program_id
                .map(|addr| addr.parse().unwrap()),
        )
        .wormhole_post_message_shim_event_authority(
            combined_config
                .solana_wormhole_post_message_shim_event_authority
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

    let btc_client_auth = if let Some(api_key) = combined_config.btc_api_key {
        AuthOptions::XApiKey(api_key)
    } else if let Some(basic_auth) = combined_config.btc_basic_auth {
        let (user, password) = basic_auth.split_once(':').unwrap();
        AuthOptions::BasicAuth(user.to_string(), password.to_string())
    } else {
        AuthOptions::None
    };

    let zcash_client_auth = if let Some(api_key) = combined_config.zcash_api_key {
        AuthOptions::XApiKey(api_key)
    } else if let Some(basic_auth) = combined_config.zcash_basic_auth {
        let (user, password) = basic_auth.split_once(':').unwrap();
        AuthOptions::BasicAuth(user.to_string(), password.to_string())
    } else {
        AuthOptions::None
    };

    let btc_bridge_client =
        UTXOBridgeClient::<Bitcoin>::new(combined_config.btc_endpoint.unwrap(), btc_client_auth);

    let zcash_bridge_client =
        UTXOBridgeClient::<Zcash>::new(combined_config.zcash_endpoint.unwrap(), zcash_client_auth);

    let eth_light_client = LightClientBuilder::default()
        .endpoint(combined_config.near_rpc.clone())
        .chain(Some(ChainKind::Eth))
        .light_client_id(
            combined_config
                .eth_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    let btc_light_client = LightClientBuilder::default()
        .endpoint(combined_config.near_rpc.clone())
        .chain(Some(ChainKind::Btc))
        .light_client_id(
            combined_config
                .btc_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    let zcash_light_client = LightClientBuilder::default()
        .endpoint(combined_config.near_rpc.clone())
        .chain(Some(ChainKind::Zcash))
        .light_client_id(
            combined_config
                .zcash_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    OmniConnectorBuilder::default()
        .network(Some(network.into()))
        .near_bridge_client(Some(near_bridge_client))
        .eth_bridge_client(Some(eth_bridge_client))
        .base_bridge_client(Some(base_bridge_client))
        .arb_bridge_client(Some(arb_bridge_client))
        .bnb_bridge_client(Some(bnb_bridge_client))
        .solana_bridge_client(Some(solana_bridge_client))
        .wormhole_bridge_client(Some(wormhole_bridge_client))
        .btc_bridge_client(Some(btc_bridge_client))
        .zcash_bridge_client(Some(zcash_bridge_client))
        .eth_light_client(Some(eth_light_client))
        .btc_light_client(Some(btc_light_client))
        .zcash_light_client(Some(zcash_light_client))
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
