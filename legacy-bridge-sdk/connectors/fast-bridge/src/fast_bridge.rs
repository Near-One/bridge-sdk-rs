use base64::prelude::*;
use borsh::BorshSerialize;
use derive_builder::Builder;
use ethers::prelude::*;
use legacy_bridge_connector_common::result::{BridgeSdkError, Result};
use legacy_near_rpc_client::ChangeRequest;
use near_crypto::SecretKey;
use near_primitives::{hash::CryptoHash, types::AccountId};
use sha3::{Digest, Keccak256};
use std::{str::FromStr, sync::Arc};

abigen!(
    FastBridgeContract,
    r#"[
      function transferTokens(address _token, address payable _recipient, uint256 _nonce, uint256 _amount, string _unlock_recipient, uint256 _valid_till_block_height)
    ]"#
);

#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq)]
pub struct EthAddress(pub [u8; 20]);

#[derive(BorshSerialize, Debug, Clone, PartialEq)]
pub struct TransferDataEthereum {
    pub token_near: AccountId,
    pub token_eth: EthAddress,
    pub amount: u128,
}

#[derive(BorshSerialize, Debug, Clone, PartialEq)]
pub struct TransferDataNear {
    pub token: AccountId,
    pub amount: u128,
}

#[derive(BorshSerialize, Debug, Clone, PartialEq)]
pub struct TransferMessage {
    pub valid_till: u64,
    pub transfer: TransferDataEthereum,
    pub fee: TransferDataNear,
    pub recipient: EthAddress,
    pub valid_till_block_height: Option<u64>,
    pub aurora_sender: Option<EthAddress>,
}

#[derive(Builder)]
pub struct FastBridge {
    #[doc = r"Ethereum RPC endpoint. Required for `transfer_on_eth`, `lp_unlock`"]
    eth_endpoint: Option<String>,
    #[doc = r"Ethereum chain id. Required for `transfer_on_eth`, `lp_unlock`"]
    eth_chain_id: Option<u64>,
    #[doc = r"Ethereum private key. Required for `transfer_on_eth`"]
    eth_private_key: Option<String>,
    #[doc = r"NEAR RPC endpoint. Required for `transfer`, `lp_unlock`, `withdraw`"]
    near_endpoint: Option<String>,
    #[doc = r"NEAR private key. Required for `transfer`, `lp_unlock`, `withdraw`"]
    near_private_key: Option<String>,
    #[doc = r"NEAR account id of the transaction signer. Required for `transfer`, `lp_unlock`, `withdraw`"]
    near_signer: Option<String>,
    #[doc = r"Fast Bridge account id on Near. Required for `transfer`, `lp_unlock`, `withdraw`"]
    fast_bridge_account_id: Option<String>,
    #[doc = r"Fast bridge address on Ethereum. Required for `transfer_on_eth`"]
    fast_bridge_address: Option<String>,
}

impl FastBridge {
    /// Initiates fast bridge transfer by sending tokens to the fast bridge contract on NEAR
    #[tracing::instrument(skip_all, name = "TRANSFER")]
    pub async fn transfer(
        &self,
        token_id: AccountId,
        amount: u128,
        fee_amount: u128,
        eth_token_address: Address,
        recipient: Address,
        valid_till: u64,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;
        let fast_bridge_account_id = self.fast_bridge_account_id()?.to_string();

        let message = TransferMessage {
            valid_till,
            transfer: TransferDataEthereum {
                token_near: token_id.clone(),
                token_eth: EthAddress(eth_token_address.0),
                amount,
            },
            fee: TransferDataNear {
                token: token_id.clone(),
                amount: fee_amount,
            },
            recipient: EthAddress(recipient.0),
            valid_till_block_height: None,
            aurora_sender: None,
        };

        let mut buffer: Vec<u8> = Vec::new();
        message
            .serialize(&mut buffer)
            .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?;
        let msg = BASE64_STANDARD.encode(&buffer);

        let args = format!(
            r#"{{"receiver_id":"{fast_bridge_account_id}","amount":"{amount}","msg":"{msg}"}}"#
        )
        .to_string()
        .into_bytes();

        let tx_hash = legacy_near_rpc_client::change(
            near_endpoint,
            ChangeRequest {
                signer: self.near_signer()?,
                receiver_id: fast_bridge_account_id.parse().map_err(|_| {
                    BridgeSdkError::ConfigError("Invalid fast bridge account id".to_string())
                })?,
                method_name: "transfer".to_string(),
                args,
                gas: 20_000_000_000_000,
                deposit: 1,
            },
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent tokens to the fast bridge contract"
        );

        Ok(tx_hash)
    }

    /// Completes fast bridge transfer by sending tokens to the recipient on Ethereum. The proof from this transaction is to be used to unlock tokens on NEAR for unlock_recipient
    #[tracing::instrument(skip_all, name = "TRANSFER ON ETH")]
    pub async fn complete_transfer_on_eth(
        &self,
        token: Address,
        recipient: Address,
        nonce: U256,
        amount: U256,
        unlock_recipient: String,
        valid_till_block_height: U256,
    ) -> Result<TxHash> {
        let fast_bridge = self.fast_bridge_contract()?;
        let transfer_call = fast_bridge
            .transfer_tokens(
                token,
                recipient,
                nonce,
                amount,
                unlock_recipient,
                valid_till_block_height,
            )
            .value(amount);

        let tx = transfer_call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Completed fast bridge transfer"
        );

        Ok(tx.tx_hash())
    }

    /// Unlocks tokens on Near following a successful transfer completion on Ethereum.
    #[tracing::instrument(skip_all, name = "LP UNLOCK")]
    pub async fn lp_unlock(&self, tx_hash: TxHash) -> Result<CryptoHash> {
        let eth_endpoint = self.eth_endpoint()?;
        let near_endpoint = self.near_endpoint()?;

        let event_topic = H256::from_str(&hex::encode(Keccak256::digest(
            "TransferTokens(uint256,address,address,address,uint256,string,bytes32)".as_bytes(),
        )))
        .map_err(|err| BridgeSdkError::UnknownError(err.to_string()))?;

        let proof =
            legacy_eth_proof::get_proof_for_event(tx_hash, event_topic, eth_endpoint).await?;

        let serialized_proof = serde_json::to_string(&proof).unwrap();
        let args = format!(r#"{{"proof":{serialized_proof}}}"#)
            .to_string()
            .into_bytes();

        tracing::debug!("Retrieved Ethereum proof");

        let tx_hash = legacy_near_rpc_client::change(
            near_endpoint,
            ChangeRequest {
                signer: self.near_signer()?,
                receiver_id: self.fast_bridge_account_id()?.parse().map_err(|_| {
                    BridgeSdkError::ConfigError("Invalid fast bridge account id".to_string())
                })?,
                method_name: "lp_unlock".to_string(),
                args,
                gas: 120_000_000_000_000,
                deposit: 0,
            },
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent lp unlock transaction"
        );

        Ok(tx_hash)
    }

    /// Withdraw tokens from the fast bridge contract.
    #[tracing::instrument(skip_all, name = "WITHDRAW")]
    pub async fn withdraw(
        &self,
        token_id: AccountId,
        amount: Option<U128>,
        recipient_id: Option<AccountId>,
        msg: Option<String>,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;

        let mut json = format!(r#"{{"token_id": "{token_id}""#);
        if let Some(recipient_id) = recipient_id {
            json.push_str(&format!(r#","recipient_id": "{recipient_id}""#));
        }
        if let Some(amount) = amount {
            json.push_str(&format!(r#","amount": "{amount}""#));
        }
        if let Some(msg) = msg {
            json.push_str(&format!(r#","msg": "{msg}""#));
        }
        json.push('}');

        let args = json.to_string().into_bytes();

        let tx_hash = legacy_near_rpc_client::change(
            near_endpoint,
            ChangeRequest {
                signer: self.near_signer()?,
                receiver_id: self.fast_bridge_account_id()?.parse().map_err(|_| {
                    BridgeSdkError::ConfigError("Invalid fast bridge account id".to_string())
                })?,
                method_name: "withdraw".to_string(),
                args,
                gas: 20_000_000_000_000,
                deposit: 0,
            },
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent withdraw transaction"
        );

        Ok(tx_hash)
    }

    fn near_signer(&self) -> Result<near_crypto::InMemorySigner> {
        let near_private_key =
            self.near_private_key
                .as_ref()
                .ok_or(BridgeSdkError::ConfigError(
                    "Near account private key is not set".to_string(),
                ))?;
        let near_signer = self
            .near_signer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near signer account id is not set".to_string(),
            ))?;

        Ok(near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(near_signer).map_err(|_| {
                BridgeSdkError::ConfigError("Invalid near signer account id".to_string())
            })?,
            SecretKey::from_str(near_private_key)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid near private key".to_string()))?,
        ))
    }

    fn fast_bridge_contract(
        &self,
    ) -> Result<FastBridgeContract<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let eth_endpoint = self
            .eth_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum rpc endpoint is not set".to_string(),
            ))?;

        let eth_provider = Provider::<Http>::try_from(eth_endpoint).map_err(|_| {
            BridgeSdkError::ConfigError("Invalid ethereum rpc endpoint url".to_string())
        })?;

        let wallet = self.eth_signer()?;

        let signer = SignerMiddleware::new(eth_provider, wallet);
        let client = Arc::new(signer);

        Ok(FastBridgeContract::new(self.fast_bridge_address()?, client))
    }

    fn eth_signer(&self) -> Result<LocalWallet> {
        let eth_private_key = self
            .eth_private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum private key is not set".to_string(),
            ))?;

        let eth_chain_id = *self
            .eth_chain_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum chain id is not set".to_string(),
            ))?;

        let private_key_bytes = hex::decode(eth_private_key).map_err(|_| {
            BridgeSdkError::ConfigError(
                "Ethereum private key is not a valid hex string".to_string(),
            )
        })?;

        if private_key_bytes.len() != 32 {
            return Err(BridgeSdkError::ConfigError(
                "Ethereum private key is of invalid length".to_string(),
            ));
        }

        Ok(LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid ethereum private key".to_string()))?
            .with_chain_id(eth_chain_id))
    }

    fn fast_bridge_address(&self) -> Result<Address> {
        self.fast_bridge_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Fast bridge address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "fast_bridge_address is not a valid Ethereum address".to_string(),
                    )
                })
            })
    }

    fn eth_endpoint(&self) -> Result<&str> {
        Ok(self
            .eth_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum rpc endpoint is not set".to_string(),
            ))?)
    }

    fn near_endpoint(&self) -> Result<&str> {
        Ok(self
            .near_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near rpc endpoint is not set".to_string(),
            ))?)
    }

    fn fast_bridge_account_id(&self) -> Result<&str> {
        Ok(self
            .fast_bridge_account_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Fast bridge account id is not set".to_string(),
            ))?)
    }
}
