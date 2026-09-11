use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::Network,
    primitives::{Address, Bytes, TxHash, U256},
    providers::{DynProvider, Provider},
    sol,
    sol_types::SolEvent,
};
use error::Result;
use ethereum_types::H256 as EthH256;
use near_mpc_contract_interface::types::EvmFinality;
use omni_types::prover_result::ProofKind;
use omni_types::{near_events::OmniBridgeEvent, OmniAddress};
use omni_types::{prover_args::EvmProof, ChainKind};
use omni_types::{EvmAddress, Fee};
use sha3::{Digest, Keccak256};

use crate::error::EvmBridgeClientError;

pub use builder::EvmBridgeClientBuilder;

mod builder;
pub mod error;

const DEPLOY_TOKEN_GAS: u64 = 500_000;
const FIN_TRANSFER_GAS: u64 = 250_000;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface OmniBridge {
        struct MetadataPayload {
            string token;
            string name;
            string symbol;
            uint8 decimals;
        }

        struct TransferMessagePayload {
            uint64 destinationNonce;
            uint8 originChain;
            uint64 originNonce;
            address tokenAddress;
            uint128 amount;
            address recipient;
            string feeRecipient;
            bytes message;
        }
        struct TransferMessagePayloadWithoutMessage {
            uint64 destinationNonce;
            uint8 originChain;
            uint64 originNonce;
            address tokenAddress;
            uint128 amount;
            address recipient;
            string feeRecipient;
        }

        function deployToken(bytes signatureData, MetadataPayload metadata) external returns (address);
        function finTransfer(bytes, TransferMessagePayload) external;
        function finTransfer(bytes, TransferMessagePayloadWithoutMessage) external;
        function initTransfer(address tokenAddress, uint128 amount, uint128 fee, uint128 nativeFee, string recipient, string message) external payable;
        function logMetadata(address tokenAddress) external payable;
        function completedTransfers(uint64) external view returns (bool);

        event InitTransfer(address indexed sender, address indexed tokenAddress, uint64 indexed originNonce, uint128 amount, uint128 fee, uint128 nativeFee, string recipient, string message);
        event DeployToken(address indexed tokenAddress, string token, string name, string symbol, uint8 decimals, uint8 originDecimals);
        event FinTransfer(uint8 originChain, uint64 originNonce, address tokenAddress, uint128 amount, address recipient, string feeRecipient);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ERC20 {
        function allowance(address owner, address spender) public view returns (uint256 remaining);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface WormholeCore {
        function messageFee() external view returns (uint256);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface HlBridgeToken {
        event CoreReceived(address indexed sender, uint8 indexed action, uint64 indexed coreNonce, uint256 amount, bytes data);
    }
}

sol! {
    /// HyperEVM-only `OmniBridgeWormhole` subclass (`HlOmniBridgeWormhole`).
    ///
    /// The HyperCore callback is a system transaction whose logs never reach
    /// the block's `logsBloom`, so nothing published from it would be visible
    /// to Wormhole guardians. It therefore only *commits* the payload
    /// (`PreInitTransfer`); `triggerPendingInitTransfer` submits it later from
    /// an ordinary transaction, under the same `originNonce`.
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface HlOmniBridge {
        function triggerPendingInitTransfer(uint64 originNonce, address tokenAddress, address sender, uint128 amount, uint128 fee, string recipient, string message) external payable;
        function pendingInitTransfers(uint64 originNonce) external view returns (bytes32);
        function currentOriginNonce() external view returns (uint64);

        event PreInitTransfer(uint64 indexed originNonce, address indexed tokenAddress, address indexed sender, uint64 coreNonce, uint128 amount, uint128 fee, string recipient, string message);
    }
}

// Helper type for InitTransferFilter compatibility
#[derive(Debug, Clone)]
pub struct InitTransferFilter {
    pub sender: Address,
    pub token_address: Address,
    pub origin_nonce: u64,
    pub amount: u128,
    pub fee: u128,
    pub native_fee: u128,
    pub recipient: String,
    pub message: String,
}

/// Decoded `HlBridgeToken.CoreReceived` event. `sender` is the originating
/// HyperCore user (passed through as `from`); `data` is the full
/// `tag || abi.encoded payload` bytes.
#[derive(Debug, Clone)]
pub struct CoreReceivedFilter {
    pub sender: Address,
    pub action: u8,
    pub core_nonce: u64,
    pub amount: U256,
    pub data: Bytes,
}

/// Decoded `HlOmniBridge.PreInitTransfer`, and the input to
/// [`EvmBridgeClient::trigger_pending_init_transfer`].
#[derive(Debug, Clone)]
pub struct PreInitTransferFilter {
    /// Commitment key, and the `originNonce` the later `InitTransfer` carries.
    pub origin_nonce: u64,
    pub token_address: Address,
    /// The originating HyperCore user, unlike `InitTransfer`'s `sender`.
    pub sender: Address,
    pub core_nonce: u64,
    pub amount: u128,
    /// Token-denominated; `nativeFee` is always 0 on this path.
    pub fee: u128,
    pub recipient: String,
    pub message: String,
}

/// The token's `CoreReceived` and the bridge's `PreInitTransfer`, paired from
/// one HyperCore bridging callback (action `0x01`).
#[derive(Debug, Clone)]
pub struct CoreInitiatedTransfer {
    pub pre_init_transfer: PreInitTransferFilter,
    pub core_received: CoreReceivedFilter,
}

/// Bridging NEAR-originated NEP-141 tokens to EVM and back
#[derive(Clone)]
pub struct EvmBridgeClient {
    endpoint: String,
    provider: DynProvider,
    signer_provider: Option<DynProvider>,
    signer_address: Option<Address>,
    omni_bridge_address: Option<Address>,
    wormhole_core_address: Option<Address>,
    mpc_finality: Option<EvmFinality>,
}

impl EvmBridgeClient {
    /// Gets the block number of a transaction
    pub async fn get_tx_block_number(&self, tx_hash: TxHash) -> Result<u64> {
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError("Transaction missing".to_string())
            })?;

        let block_number = tx.block_number.ok_or_else(|| {
            EvmBridgeClientError::BlockchainDataError("Block number missing for tx".to_string())
        })?;

        Ok(block_number)
    }

    /// Gets last finalized block number on EVM chain
    pub async fn get_last_block_number(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError("Latest block missing".to_string())
            })?;

        Ok(block.header.number)
    }

    /// Returns the configured MPC finality level for this chain.
    pub fn mpc_finality(&self) -> Result<EvmFinality> {
        self.mpc_finality.clone().ok_or_else(|| {
            EvmBridgeClientError::ConfigError("MPC finality is not configured".to_string())
        })
    }

    /// Verifies that `tx_hash` has reached the configured MPC finality level
    /// and returns that finality so it can be embedded in the MPC sign payload.
    pub async fn check_mpc_finality(&self, tx_hash: TxHash) -> Result<EvmFinality> {
        let finality = self.mpc_finality()?;

        let block_tag = match &finality {
            EvmFinality::Latest => alloy::eips::BlockNumberOrTag::Latest,
            EvmFinality::Safe => alloy::eips::BlockNumberOrTag::Safe,
            EvmFinality::Finalized => alloy::eips::BlockNumberOrTag::Finalized,
            _ => {
                return Err(EvmBridgeClientError::ConfigError(
                    "Unsupported EVM finality variant".to_string(),
                ));
            }
        };

        let tx_block_number = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(EvmBridgeClientError::MpcFinalityNotReached)?
            .block_number
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError(
                    "Mined transaction receipt missing block number".to_string(),
                )
            })?;

        let finalized_block = self
            .provider
            .get_block_by_number(block_tag)
            .await?
            .ok_or_else(|| {
                EvmBridgeClientError::BlockchainDataError(
                    "Block not found for the given finality tag".to_string(),
                )
            })?
            .header
            .number;

        if tx_block_number > finalized_block {
            return Err(EvmBridgeClientError::MpcFinalityNotReached);
        }

        Ok(finality)
    }

    /// Checks if the transfer is already finalised on EVM
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let omni_bridge = self.omni_bridge()?;
        let is_finalised = omni_bridge.completedTransfers(nonce).call().await?;

        Ok(is_finalised)
    }

    /// Logs an ERC-20 token metadata
    #[tracing::instrument(skip_all, name = "LOG METADATA")]
    pub async fn log_metadata(
        &self,
        address: EvmAddress,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge = self.omni_bridge()?;
        let token_address = Address::from_slice(&address.0);

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.logMetadata(token_address),
            tx_nonce,
            self.get_wormhole_fee().await.ok(),
            None,
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Deploys an ERC-20 token representing a bridged version of a token from another chain. Requires a receipt from `log_metadata` transaction on Near
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn deploy_token(
        &self,
        transfer_log: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge = self.omni_bridge()?;

        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = transfer_log
        else {
            return Err(EvmBridgeClientError::InvalidArgument(format!(
                "Expected LogMetadataEvent but got {transfer_log:?}"
            )));
        };

        let payload = OmniBridge::MetadataPayload {
            token: metadata_payload.token,
            name: metadata_payload.name,
            symbol: metadata_payload.symbol,
            decimals: metadata_payload.decimals,
        };

        let serialized_signature = signature.to_bytes();
        assert!(serialized_signature.len() == 65);

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.deployToken(Bytes::from(serialized_signature), payload),
            tx_nonce,
            self.get_wormhole_fee().await.ok(),
            Some(DEPLOY_TOKEN_GAS),
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent new bridge token transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Burns bridged tokens on EVM. The proof from this transaction is then used to withdraw the corresponding tokens on Near
    #[tracing::instrument(skip_all, name = "EVM INIT TRANSFER")]
    pub async fn init_transfer(
        &self,
        token: alloy::primitives::Address,
        amount: u128,
        receiver: OmniAddress,
        fee: Fee,
        message: String,
        mut tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge_address = self.omni_bridge_address()?;
        let omni_bridge = self.omni_bridge()?;
        let signer_address = self.signer_address()?;
        let signer_provider = self.signer_provider()?;

        // Handle token approval if not native token
        if !token.is_zero() {
            let erc20 = ERC20::new(token, &signer_provider);

            let allowance_result = erc20
                .allowance(*signer_address, omni_bridge_address)
                .call()
                .await?;

            let amount_u256 = U256::from(amount);
            if allowance_result < amount_u256 {
                let mut approval_call = erc20.approve(omni_bridge_address, amount_u256);
                if let Some(nonce) = tx_nonce {
                    approval_call = approval_call.nonce(nonce.to::<u64>());
                }

                approval_call.send().await?.get_receipt().await?;
                tx_nonce = tx_nonce.map(|n| n + U256::from(1));

                tracing::debug!("Approved tokens for spending");
            }
        }

        let mut value = U256::from(fee.native_fee.0);

        if let Ok(wormhole_fee) = self.get_wormhole_fee().await {
            value += wormhole_fee;
        }

        if token.is_zero() {
            value += U256::from(amount);
        }

        let call_builder = self.prepare_tx_for_sending(
            omni_bridge.initTransfer(
                token,
                amount,
                fee.fee.into(),
                fee.native_fee.into(),
                receiver.to_string(),
                message,
            ),
            tx_nonce,
            Some(value),
            None,
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            "Sent transfer transaction"
        );

        Ok(receipt.transaction_hash)
    }

    /// Mints the corresponding bridged tokens on EVM
    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER")]
    pub async fn fin_transfer(
        &self,
        chain_kind: ChainKind,
        transfer_log: OmniBridgeEvent,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let omni_bridge = self.omni_bridge()?;

        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(EvmBridgeClientError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {transfer_log:?}"
            )));
        };

        match chain_kind {
            ChainKind::HyperEvm | ChainKind::Abs => {
                let bridge_deposit = OmniBridge::TransferMessagePayload {
                    destinationNonce: message_payload.destination_nonce,
                    originChain: message_payload.transfer_id.origin_chain.into(),
                    originNonce: message_payload.transfer_id.origin_nonce,
                    tokenAddress: Self::convert_omni_address(message_payload.token_address)?,
                    amount: message_payload.amount.into(),
                    recipient: Self::convert_omni_address(message_payload.recipient)?,
                    feeRecipient: message_payload
                        .fee_recipient
                        .map_or_else(String::new, |addr| addr.to_string()),
                    message: Bytes::from(message_payload.message),
                };

                let call_builder = self.prepare_tx_for_sending(
                    omni_bridge.finTransfer_0(Bytes::from(signature.to_bytes()), bridge_deposit),
                    tx_nonce,
                    self.get_wormhole_fee().await.ok(),
                    Some(FIN_TRANSFER_GAS),
                );

                let pending = call_builder.send().await?;
                let tx_hash = *pending.tx_hash();
                tracing::info!(
                    tx_hash = format!("{tx_hash:?}"),
                    "Sent finalize transfer transaction"
                );
                Ok(tx_hash)
            }
            ChainKind::Eth | ChainKind::Base | ChainKind::Arb | ChainKind::Bnb | ChainKind::Pol => {
                let bridge_deposit = OmniBridge::TransferMessagePayloadWithoutMessage {
                    destinationNonce: message_payload.destination_nonce,
                    originChain: message_payload.transfer_id.origin_chain.into(),
                    originNonce: message_payload.transfer_id.origin_nonce,
                    tokenAddress: Self::convert_omni_address(message_payload.token_address)?,
                    amount: message_payload.amount.into(),
                    recipient: Self::convert_omni_address(message_payload.recipient)?,
                    feeRecipient: message_payload
                        .fee_recipient
                        .map_or_else(String::new, |addr| addr.to_string()),
                };

                let call_builder = self.prepare_tx_for_sending(
                    omni_bridge.finTransfer_1(Bytes::from(signature.to_bytes()), bridge_deposit),
                    tx_nonce,
                    self.get_wormhole_fee().await.ok(),
                    Some(FIN_TRANSFER_GAS),
                );

                let pending = call_builder.send().await?;
                let tx_hash = *pending.tx_hash();
                tracing::info!(
                    tx_hash = format!("{tx_hash:?}"),
                    "Sent finalize transfer transaction"
                );
                Ok(tx_hash)
            }
            ChainKind::Near
            | ChainKind::Sol
            | ChainKind::Fogo
            | ChainKind::Btc
            | ChainKind::Zcash
            | ChainKind::Strk
            | ChainKind::Aptos => Err(EvmBridgeClientError::InvalidArgument(format!(
                "Expected evm chain but got {chain_kind:?}"
            ))),
        }
    }

    pub async fn get_proof_for_event(
        &self,
        tx_hash: TxHash,
        proof_kind: ProofKind,
    ) -> Result<EvmProof> {
        let event_signature = match proof_kind {
            ProofKind::DeployToken => "DeployToken(address,string,string,string,uint8,uint8)",
            ProofKind::InitTransfer => {
                "InitTransfer(address,address,uint64,uint128,uint128,uint128,string,string)"
            }
            ProofKind::FinTransfer => "FinTransfer(uint8,uint64,address,uint128,address,string)",
            ProofKind::LogMetadata => "LogMetadata(address,string,string,uint8)",
        };

        let hash_bytes = Keccak256::digest(event_signature.as_bytes());
        let event_topic = EthH256::from_slice(&hash_bytes);

        // Convert TxHash (B256) to ethereum_types::H256
        let tx_hash_primitive = EthH256::from_slice(tx_hash.as_slice());

        let proof =
            eth_proof::get_proof_for_event(tx_hash_primitive, event_topic, &self.endpoint).await?;

        Ok(proof)
    }

    pub async fn get_transfer_event(&self, tx_hash: TxHash) -> Result<InitTransferFilter> {
        let rpc_log = self.get_init_transfer_log(tx_hash).await?;

        let log_data = rpc_log.into_inner();

        let decoded = OmniBridge::InitTransfer::decode_log(&log_data).map_err(|err| {
            EvmBridgeClientError::BlockchainDataError(format!("Failed to decode event log: {err}"))
        })?;

        Ok(InitTransferFilter {
            sender: decoded.sender,
            token_address: decoded.tokenAddress,
            origin_nonce: decoded.originNonce,
            amount: decoded.amount,
            fee: decoded.fee,
            native_fee: decoded.nativeFee,
            recipient: decoded.recipient.clone(),
            message: decoded.message.clone(),
        })
    }

    pub async fn get_init_transfer_log(&self, tx_hash: TxHash) -> Result<alloy::rpc::types::Log> {
        self.get_event_log(tx_hash, OmniBridge::InitTransfer::SIGNATURE)
            .await
    }

    /// Fetches the `HlBridgeToken.CoreReceived` log emitted by `hl_bridge_token`
    /// in the receipt of `tx_hash`. Use this to verify that a HyperCore-originated
    /// `sendToEvmWithData` action landed on HyperEVM as expected.
    pub async fn get_core_received_log(
        &self,
        tx_hash: TxHash,
        hl_bridge_token: Address,
    ) -> Result<alloy::rpc::types::Log> {
        let sig_hash =
            alloy::primitives::keccak256(HlBridgeToken::CoreReceived::SIGNATURE.as_bytes());

        self.get_logs(tx_hash)
            .await?
            .into_iter()
            .find(|log| {
                log.address() == hl_bridge_token
                    && log
                        .topics()
                        .first()
                        .is_some_and(|topic| topic.0 == sig_hash.0)
            })
            .ok_or(EvmBridgeClientError::BlockchainDataError(format!(
                "CoreReceived log from {hl_bridge_token:?} missing in tx {tx_hash}"
            )))
    }

    /// The single commitment in `tx_hash`, ready to hand back to
    /// [`Self::trigger_pending_init_transfer`]. Errors rather than guessing if
    /// the transaction carries several; pick by `sender` + `core_nonce` from
    /// [`Self::get_pre_init_transfer_events`] then.
    pub async fn get_pre_init_transfer_event(
        &self,
        tx_hash: TxHash,
    ) -> Result<PreInitTransferFilter> {
        let mut events = self.get_pre_init_transfer_events(tx_hash).await?;

        match events.len() {
            0 => Err(EvmBridgeClientError::BlockchainDataError(format!(
                "PreInitTransfer log missing in tx {tx_hash}"
            ))),
            1 => Ok(events.remove(0)),
            n => Err(EvmBridgeClientError::BlockchainDataError(format!(
                "tx {tx_hash} carries {n} PreInitTransfer logs; disambiguate by sender and core nonce"
            ))),
        }
    }

    /// Every `PreInitTransfer` in `tx_hash`, in log order. Matches the emitter
    /// address too — any contract can emit a log with this signature, but only
    /// the bridge's is a commitment.
    pub async fn get_pre_init_transfer_events(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<PreInitTransferFilter>> {
        let omni_bridge_address = self.omni_bridge_address()?;
        let sig_hash =
            alloy::primitives::keccak256(HlOmniBridge::PreInitTransfer::SIGNATURE.as_bytes());

        self.get_logs(tx_hash)
            .await?
            .into_iter()
            .filter(|log| {
                log.address() == omni_bridge_address
                    && log
                        .topics()
                        .first()
                        .is_some_and(|topic| topic.0 == sig_hash.0)
            })
            .map(|log| {
                let decoded = HlOmniBridge::PreInitTransfer::decode_log(&log.into_inner())
                    .map_err(|err| {
                        EvmBridgeClientError::BlockchainDataError(format!(
                            "Failed to decode PreInitTransfer log: {err}"
                        ))
                    })?;

                Ok(PreInitTransferFilter {
                    origin_nonce: decoded.originNonce,
                    token_address: decoded.tokenAddress,
                    sender: decoded.sender,
                    core_nonce: decoded.coreNonce,
                    amount: decoded.amount,
                    fee: decoded.fee,
                    recipient: decoded.recipient.clone(),
                    message: decoded.message.clone(),
                })
            })
            .collect()
    }

    /// Submits a committed transfer: burns the parked tokens and publishes the
    /// Wormhole message. Permissionless on-chain.
    ///
    /// Pass the payload exactly as `PreInitTransfer` reported it — the bridge
    /// re-hashes it and reverts with `PayloadMismatch` on any re-encoding.
    #[tracing::instrument(skip_all, name = "EVM TRIGGER PENDING INIT TRANSFER")]
    pub async fn trigger_pending_init_transfer(
        &self,
        pre_init: &PreInitTransferFilter,
        tx_nonce: Option<U256>,
    ) -> Result<TxHash> {
        let hl_omni_bridge = self.hl_omni_bridge()?;

        let call_builder = self.prepare_tx_for_sending(
            hl_omni_bridge.triggerPendingInitTransfer(
                pre_init.origin_nonce,
                pre_init.token_address,
                pre_init.sender,
                pre_init.amount,
                pre_init.fee,
                pre_init.recipient.clone(),
                pre_init.message.clone(),
            ),
            tx_nonce,
            // Wormhole message fee; `nativeFee` is 0 on this path.
            self.get_wormhole_fee().await.ok(),
            None,
        );

        let receipt = call_builder.send().await?.get_receipt().await?;

        tracing::info!(
            tx_hash = format!("{:?}", receipt.transaction_hash),
            origin_nonce = pre_init.origin_nonce,
            "Submitted pending HyperCore init transfer"
        );

        Ok(receipt.transaction_hash)
    }

    /// Whether `origin_nonce` still holds an unsubmitted commitment. Zero means
    /// never queued or already submitted — indistinguishable on-chain.
    pub async fn is_init_transfer_pending(&self, origin_nonce: u64) -> Result<bool> {
        let hl_omni_bridge = self.hl_omni_bridge()?;
        let commitment = hl_omni_bridge
            .pendingInitTransfers(origin_nonce)
            .call()
            .await?;

        Ok(!commitment.is_zero())
    }

    /// Highest `originNonce` assigned. Commitments are enumerable against it,
    /// which is how a submitter finds them without relying on logs.
    pub async fn current_origin_nonce(&self) -> Result<u64> {
        let hl_omni_bridge = self.hl_omni_bridge()?;
        let nonce = hl_omni_bridge.currentOriginNonce().call().await?;

        Ok(nonce)
    }

    /// Correlates `PreInitTransfer` and `CoreReceived` in the same HyperEVM tx
    /// — the only place the transfer can be attributed back to the Core
    /// account that started it.
    pub async fn parse_core_initiated_transfer(
        &self,
        tx_hash: TxHash,
        hl_bridge_token: Address,
    ) -> Result<CoreInitiatedTransfer> {
        let pre_init_transfer = self.get_pre_init_transfer_event(tx_hash).await?;

        let core_log = self.get_core_received_log(tx_hash, hl_bridge_token).await?;
        let decoded =
            HlBridgeToken::CoreReceived::decode_log(&core_log.into_inner()).map_err(|err| {
                EvmBridgeClientError::BlockchainDataError(format!(
                    "Failed to decode CoreReceived log: {err}"
                ))
            })?;

        let HlBridgeToken::CoreReceived {
            sender,
            action,
            coreNonce,
            amount,
            data,
        } = decoded.data;

        Ok(CoreInitiatedTransfer {
            pre_init_transfer,
            core_received: CoreReceivedFilter {
                sender,
                action,
                core_nonce: coreNonce,
                amount,
                data,
            },
        })
    }

    pub async fn get_deploy_token_log(&self, tx_hash: TxHash) -> Result<alloy::rpc::types::Log> {
        self.get_event_log(tx_hash, OmniBridge::DeployToken::SIGNATURE)
            .await
    }

    pub async fn get_fin_transfer_log(&self, tx_hash: TxHash) -> Result<alloy::rpc::types::Log> {
        self.get_event_log(tx_hash, OmniBridge::FinTransfer::SIGNATURE)
            .await
    }

    pub async fn get_log_metadata_log(&self, tx_hash: TxHash) -> Result<alloy::rpc::types::Log> {
        // `LogMetadata` is not declared in the `sol!` binding, so use the signature
        // literal (the same one `get_proof_for_event` uses for `ProofKind::LogMetadata`).
        self.get_event_log(tx_hash, "LogMetadata(address,string,string,uint8)")
            .await
    }

    async fn get_event_log(
        &self,
        tx_hash: TxHash,
        event_signature: &str,
    ) -> Result<alloy::rpc::types::Log> {
        let sig_hash = alloy::primitives::keccak256(event_signature.as_bytes());

        self.get_logs(tx_hash)
            .await?
            .into_iter()
            .find(|log| {
                log.topics()
                    .first()
                    .is_some_and(|topic| topic.0 == sig_hash.0)
            })
            .ok_or(EvmBridgeClientError::BlockchainDataError(format!(
                "Event log for '{event_signature}' missing in tx {tx_hash}"
            )))
    }

    async fn get_logs(&self, tx_hash: TxHash) -> Result<Vec<alloy::rpc::types::Log>> {
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(EvmBridgeClientError::BlockchainDataError(
                "Transaction receipt missing".to_string(),
            ))?;

        Ok(receipt.inner.into_logs())
    }

    pub fn prepare_tx_for_sending<P, D, N>(
        &self,
        mut call_builder: CallBuilder<P, D, N>,
        tx_nonce: Option<U256>,
        value: Option<U256>,
        gas: Option<u64>,
    ) -> CallBuilder<P, D, N>
    where
        P: Provider<N>,
        D: CallDecoder,
        N: Network,
    {
        if let Some(nonce) = tx_nonce {
            call_builder = call_builder.nonce(nonce.to::<u64>());
        }

        if let Some(value) = value {
            call_builder = call_builder.value(value);
        }

        if let Some(gas) = gas {
            call_builder = call_builder.gas(gas);
        }

        call_builder
    }

    async fn get_wormhole_fee(&self) -> Result<U256> {
        let wormhole_address = self.wormhole_core_address()?;
        let wormhole = WormholeCore::new(wormhole_address, &self.provider);
        let fee = wormhole.messageFee().call().await?;
        Ok(fee)
    }

    pub fn omni_bridge_address(&self) -> Result<Address> {
        self.omni_bridge_address
            .ok_or(EvmBridgeClientError::ConfigError(
                "OmniBridge address is not set".to_string(),
            ))
    }

    pub fn wormhole_core_address(&self) -> Result<Address> {
        self.wormhole_core_address
            .ok_or(EvmBridgeClientError::ConfigError(
                "Wormhole core address is not set".to_string(),
            ))
    }

    fn omni_bridge(&self) -> Result<OmniBridge::OmniBridgeInstance<&DynProvider>> {
        let omni_bridge_address = self.omni_bridge_address()?;
        Ok(OmniBridge::new(
            omni_bridge_address,
            self.signer_provider()?,
        ))
    }

    /// [`Self::omni_bridge`] through the HyperEVM-only ABI; reverts elsewhere.
    fn hl_omni_bridge(&self) -> Result<HlOmniBridge::HlOmniBridgeInstance<&DynProvider>> {
        let omni_bridge_address = self.omni_bridge_address()?;
        Ok(HlOmniBridge::new(
            omni_bridge_address,
            self.signer_provider()?,
        ))
    }

    fn signer_provider(&self) -> Result<&DynProvider> {
        self.signer_provider
            .as_ref()
            .ok_or(EvmBridgeClientError::ConfigError(
                "EVM private key is not set".to_string(),
            ))
    }

    fn signer_address(&self) -> Result<&Address> {
        self.signer_address
            .as_ref()
            .ok_or(EvmBridgeClientError::ConfigError(
                "EVM private key is not set".to_string(),
            ))
    }

    fn convert_omni_address(address: OmniAddress) -> Result<Address> {
        match address {
            OmniAddress::Eth(addr)
            | OmniAddress::Base(addr)
            | OmniAddress::Arb(addr)
            | OmniAddress::Bnb(addr)
            | OmniAddress::Pol(addr)
            | OmniAddress::HyperEvm(addr)
            | OmniAddress::Abs(addr) => Ok(Address::from_slice(&addr.0)),
            OmniAddress::Near(_)
            | OmniAddress::Sol(_)
            | OmniAddress::Fogo(_)
            | OmniAddress::Btc(_)
            | OmniAddress::Zcash(_)
            | OmniAddress::Strk(_)
            | OmniAddress::Aptos(_) => Err(EvmBridgeClientError::InvalidArgument(format!(
                "Unsupported address type in SignTransferEvent: {address:?}",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;

    use super::*;

    /// Lookups filter on `topic0`, so drift against the Solidity sources is
    /// silent: the log never matches and the transfer stalls after the funds
    /// have moved.
    #[test]
    fn hypercore_event_signatures_match_the_contracts() {
        assert_eq!(
            HlBridgeToken::CoreReceived::SIGNATURE,
            "CoreReceived(address,uint8,uint64,uint256,bytes)"
        );
        assert_eq!(
            HlOmniBridge::PreInitTransfer::SIGNATURE,
            "PreInitTransfer(uint64,address,address,uint64,uint128,uint128,string,string)"
        );
    }

    /// These arguments are re-hashed into the stored commitment, so a reordered
    /// or widened parameter is a `PayloadMismatch` revert, not a compile error.
    #[test]
    fn trigger_pending_init_transfer_signature_matches_the_contract() {
        assert_eq!(
            HlOmniBridge::triggerPendingInitTransferCall::SIGNATURE,
            "triggerPendingInitTransfer(uint64,address,address,uint128,uint128,string,string)"
        );
    }
}
