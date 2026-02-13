use std::sync::Arc;

use error::Result;
use starknet::{
    accounts::{Account, SingleOwnerAccount},
    core::types::{
        BlockId, BlockTag, Call, ExecutionResult, Felt, FunctionCall,
        TransactionReceiptWithBlockInfo,
    },
    macros::selector,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::LocalWallet,
};

use crate::error::StarknetBridgeClientError;
use omni_types::near_events::OmniBridgeEvent;

pub use builder::StarknetBridgeClientBuilder;

mod builder;
pub mod error;

/// Event data extracted from a Starknet `InitTransfer` receipt.
#[derive(Debug)]
pub struct StarknetInitTransferEvent {
    pub sender: Felt,
    pub token_address: Felt,
    pub origin_nonce: u64,
    pub amount: u128,
    pub fee: u128,
    pub native_token_fee: u128,
    pub recipient: String,
    pub message: String,
}

type StarknetAccount = SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>;

/// Starknet bridge client for the OmniBridge contract.
pub struct StarknetBridgeClient {
    pub(crate) provider: Arc<JsonRpcClient<HttpTransport>>,
    pub(crate) account: Option<Arc<StarknetAccount>>,
    pub(crate) omni_bridge_address: Option<Felt>,
}

impl StarknetBridgeClient {
    fn omni_bridge_address(&self) -> Result<Felt> {
        self.omni_bridge_address
            .ok_or(StarknetBridgeClientError::ConfigError(
                "OmniBridge address is not set".to_string(),
            ))
    }

    fn account(&self) -> Result<&StarknetAccount> {
        self.account
            .as_ref()
            .map(|a| a.as_ref())
            .ok_or(StarknetBridgeClientError::ConfigError(
                "Starknet private key / account address is not set".to_string(),
            ))
    }

    async fn send_and_wait(&self, calls: Vec<Call>) -> Result<Felt> {
        let account = self.account()?;

        let execution = account.execute_v3(calls);

        let tx = execution.send().await.map_err(|e| {
            StarknetBridgeClientError::AccountError(format!("Failed to send transaction: {e}"))
        })?;

        tracing::info!(
            tx_hash = format!("{:#066x}", tx.transaction_hash),
            "Submitted Starknet transaction"
        );

        self.wait_for_tx(tx.transaction_hash).await?;

        Ok(tx.transaction_hash)
    }

    async fn wait_for_tx(&self, tx_hash: Felt) -> Result<TransactionReceiptWithBlockInfo> {
        const MAX_RETRIES: u32 = 360;
        for _ in 0..MAX_RETRIES {
            match self.provider.get_transaction_receipt(tx_hash).await {
                Ok(receipt) => match receipt.receipt.execution_result() {
                    ExecutionResult::Succeeded => return Ok(receipt),
                    ExecutionResult::Reverted { reason } => {
                        return Err(StarknetBridgeClientError::TransactionError(format!(
                            "Transaction reverted: {reason}"
                        )));
                    }
                },
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        Err(StarknetBridgeClientError::TransactionError(format!(
            "Transaction {tx_hash:#066x} was not confirmed after {MAX_RETRIES} seconds"
        )))
    }

    /// Encode a u128 as a single Felt.
    fn encode_u128(v: u128) -> Felt {
        Felt::from(v)
    }

    /// Encode a u64 as a single Felt.
    fn encode_u64(v: u64) -> Felt {
        Felt::from(v)
    }

    /// Encode a u256 as two Felts: [low_u128, high_u128].
    fn encode_u256(v: [u8; 32]) -> [Felt; 2] {
        let mut low_bytes = [0u8; 16];
        let mut high_bytes = [0u8; 16];
        high_bytes.copy_from_slice(&v[..16]);
        low_bytes.copy_from_slice(&v[16..]);
        let low = u128::from_be_bytes(low_bytes);
        let high = u128::from_be_bytes(high_bytes);
        [Felt::from(low), Felt::from(high)]
    }

    /// Encode a Cairo `ByteArray` as calldata Felts.
    ///
    /// Cairo's `ByteArray` serialization:
    ///   [num_full_31byte_words, ...word_felts, pending_word, pending_word_len]
    fn encode_byte_array(s: &str) -> Vec<Felt> {
        let bytes = s.as_bytes();
        let full_chunks = bytes.len() / 31;
        let remainder = bytes.len() % 31;

        let mut felts = Vec::new();
        felts.push(Felt::from(full_chunks as u64));

        for i in 0..full_chunks {
            let chunk = &bytes[i * 31..(i + 1) * 31];
            felts.push(Felt::from_bytes_be_slice(chunk));
        }

        if remainder > 0 {
            let pending = &bytes[full_chunks * 31..];
            felts.push(Felt::from_bytes_be_slice(pending));
        } else {
            felts.push(Felt::ZERO);
        }
        felts.push(Felt::from(remainder as u64));

        felts
    }

    /// Encode a 65-byte omni-types Signature as Starknet calldata:
    ///   r(u256 = 2 Felts) + s(u256 = 2 Felts) + v(u32 = 1 Felt)
    fn encode_signature(sig_bytes: &[u8; 65]) -> Vec<Felt> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let v = u32::from(sig_bytes[64]);

        let [r_low, r_high] = Self::encode_u256(r);
        let [s_low, s_high] = Self::encode_u256(s);

        vec![r_low, r_high, s_low, s_high, Felt::from(v)]
    }

    /// Log token metadata on the Starknet OmniBridge contract.
    #[tracing::instrument(skip_all, name = "STARKNET LOG METADATA")]
    pub async fn log_metadata(&self, token: Felt) -> Result<Felt> {
        let bridge = self.omni_bridge_address()?;

        let call = Call {
            to: bridge,
            selector: selector!("log_metadata"),
            calldata: vec![token],
        };

        self.send_and_wait(vec![call]).await
    }

    /// Deploy a bridged token on Starknet using a `LogMetadataEvent` from Near.
    #[tracing::instrument(skip_all, name = "STARKNET DEPLOY TOKEN")]
    pub async fn deploy_token(&self, event: OmniBridgeEvent) -> Result<Felt> {
        let bridge = self.omni_bridge_address()?;

        let OmniBridgeEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = event
        else {
            return Err(StarknetBridgeClientError::InvalidArgument(format!(
                "Expected LogMetadataEvent but got {event:?}"
            )));
        };

        let sig_bytes: [u8; 65] = signature.to_bytes().try_into().map_err(|_| {
            StarknetBridgeClientError::InvalidArgument("Signature must be 65 bytes".to_string())
        })?;

        let mut calldata = Self::encode_signature(&sig_bytes);

        // MetadataPayload: token, name, symbol, decimals
        calldata.extend(Self::encode_byte_array(&metadata_payload.token));
        calldata.extend(Self::encode_byte_array(&metadata_payload.name));
        calldata.extend(Self::encode_byte_array(&metadata_payload.symbol));
        calldata.push(Felt::from(metadata_payload.decimals));

        let call = Call {
            to: bridge,
            selector: selector!("deploy_token"),
            calldata,
        };

        self.send_and_wait(vec![call]).await
    }

    /// Initiate a transfer from Starknet.
    ///
    /// This issues a multicall: first ERC-20 `approve`, then `init_transfer`.
    #[tracing::instrument(skip_all, name = "STARKNET INIT TRANSFER")]
    #[allow(clippy::too_many_arguments)]
    pub async fn init_transfer(
        &self,
        token: Felt,
        amount: u128,
        fee: u128,
        native_fee: u128,
        recipient: String,
        message: String,
    ) -> Result<Felt> {
        let bridge = self.omni_bridge_address()?;

        // ERC-20 approve call (amount as u256 = [low, high])
        let approve_call = Call {
            to: token,
            selector: selector!("approve"),
            calldata: vec![bridge, Self::encode_u128(amount), Felt::ZERO],
        };

        // init_transfer call
        let mut calldata = vec![
            token,
            Self::encode_u128(amount),
            Self::encode_u128(fee),
            Self::encode_u128(native_fee),
        ];
        calldata.extend(Self::encode_byte_array(&recipient));
        calldata.extend(Self::encode_byte_array(&message));

        let init_call = Call {
            to: bridge,
            selector: selector!("init_transfer"),
            calldata,
        };

        self.send_and_wait(vec![approve_call, init_call]).await
    }

    /// Finalize a transfer to Starknet using a `SignTransferEvent` from Near.
    #[tracing::instrument(skip_all, name = "STARKNET FIN TRANSFER")]
    pub async fn fin_transfer(&self, event: OmniBridgeEvent) -> Result<Felt> {
        let bridge = self.omni_bridge_address()?;

        let OmniBridgeEvent::SignTransferEvent {
            message_payload,
            signature,
        } = event
        else {
            return Err(StarknetBridgeClientError::InvalidArgument(format!(
                "Expected SignTransferEvent but got {event:?}"
            )));
        };

        let sig_bytes: [u8; 65] = signature.to_bytes().try_into().map_err(|_| {
            StarknetBridgeClientError::InvalidArgument("Signature must be 65 bytes".to_string())
        })?;
        let mut calldata = Self::encode_signature(&sig_bytes);

        calldata.push(Self::encode_u64(message_payload.destination_nonce));
        calldata.push(Felt::from(u8::from(
            message_payload.transfer_id.origin_chain,
        )));
        calldata.push(Self::encode_u64(message_payload.transfer_id.origin_nonce));

        let token_felt = Self::omni_address_to_felt(message_payload.token_address)?;
        calldata.push(token_felt);

        calldata.push(Self::encode_u128(message_payload.amount.into()));

        let recipient_felt = Self::omni_address_to_felt(message_payload.recipient)?;
        calldata.push(recipient_felt);

        let fee_recipient_str = message_payload
            .fee_recipient
            .map_or_else(String::new, |addr| addr.to_string());
        calldata.extend(Self::encode_byte_array(&fee_recipient_str));

        let call = Call {
            to: bridge,
            selector: selector!("fin_transfer"),
            calldata,
        };

        self.send_and_wait(vec![call]).await
    }

    /// Check if a transfer with the given nonce has been finalised on Starknet.
    ///
    /// The contract stores completed transfers as a bitmap:
    ///   slot = nonce / 251, bit = nonce % 251
    pub async fn is_transfer_finalised(&self, nonce: u64) -> Result<bool> {
        let bridge = self.omni_bridge_address()?;

        let slot = nonce / 251;

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: bridge,
                    entry_point_selector: selector!("completed_transfers"),
                    calldata: vec![Felt::from(slot)],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| {
                StarknetBridgeClientError::ProviderError(format!(
                    "Failed to call completed_transfers: {e}"
                ))
            })?;

        if result.is_empty() {
            return Ok(false);
        }

        let bitmap_felt = result[0];
        let bitmap_bytes = bitmap_felt.to_bytes_be();

        let bit_position = (nonce % 251) as usize;

        let byte_index = 31 - (bit_position / 8);
        let bit_in_byte = bit_position % 8;

        Ok(bitmap_bytes[byte_index] & (1 << bit_in_byte) != 0)
    }

    /// Extract an `InitTransfer` event from a Starknet transaction receipt.
    pub async fn get_transfer_event(&self, tx_hash: Felt) -> Result<StarknetInitTransferEvent> {
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| {
                StarknetBridgeClientError::ProviderError(format!(
                    "Failed to get transaction receipt: {e}"
                ))
            })?;

        let init_transfer_selector = selector!("InitTransfer");

        let events = match &receipt.receipt {
            starknet::core::types::TransactionReceipt::Invoke(r) => &r.events,
            starknet::core::types::TransactionReceipt::L1Handler(r) => &r.events,
            _ => {
                return Err(StarknetBridgeClientError::BlockchainDataError(
                    "Unexpected receipt type".to_string(),
                ));
            }
        };

        let event = events
            .iter()
            .find(|e| !e.keys.is_empty() && e.keys[0] == init_transfer_selector)
            .ok_or_else(|| {
                StarknetBridgeClientError::BlockchainDataError(
                    "InitTransfer event not found in receipt".to_string(),
                )
            })?;

        if event.keys.len() < 4 {
            return Err(StarknetBridgeClientError::BlockchainDataError(
                "InitTransfer event has too few keys".to_string(),
            ));
        }

        let sender = event.keys[1];
        let token_address = event.keys[2];
        let origin_nonce = felt_to_u64(event.keys[3])?;

        let data = &event.data;
        if data.len() < 3 {
            return Err(StarknetBridgeClientError::BlockchainDataError(
                "InitTransfer event has too few data fields".to_string(),
            ));
        }

        let amount = felt_to_u128(data[0])?;
        let fee = felt_to_u128(data[1])?;
        let native_token_fee = felt_to_u128(data[2])?;

        let (recipient, next_idx) = decode_byte_array(data, 3)?;
        let (message, _) = decode_byte_array(data, next_idx)?;

        Ok(StarknetInitTransferEvent {
            sender,
            token_address,
            origin_nonce,
            amount,
            fee,
            native_token_fee,
            recipient,
            message,
        })
    }

    fn omni_address_to_felt(address: omni_types::OmniAddress) -> Result<Felt> {
        match address {
            omni_types::OmniAddress::Strk(h256) => Ok(Felt::from_bytes_be(&h256.0)),
            other => Err(StarknetBridgeClientError::InvalidArgument(format!(
                "Expected Starknet address but got {other:?}"
            ))),
        }
    }
}

fn felt_to_u64(f: Felt) -> Result<u64> {
    let bytes = f.to_bytes_be();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(buf))
}

fn felt_to_u128(f: Felt) -> Result<u128> {
    let bytes = f.to_bytes_be();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..]);
    Ok(u128::from_be_bytes(buf))
}

/// Decode a Cairo `ByteArray` from a slice of Felts starting at `offset`.
/// Returns `(decoded_string, next_offset)`.
fn decode_byte_array(data: &[Felt], offset: usize) -> Result<(String, usize)> {
    if offset >= data.len() {
        return Err(StarknetBridgeClientError::BlockchainDataError(
            "ByteArray decode: offset out of bounds".to_string(),
        ));
    }

    let num_full_words = felt_to_u64(data[offset])? as usize;
    let mut idx = offset + 1;

    let mut bytes = Vec::new();

    for _ in 0..num_full_words {
        if idx >= data.len() {
            return Err(StarknetBridgeClientError::BlockchainDataError(
                "ByteArray decode: unexpected end of data".to_string(),
            ));
        }
        let word_bytes = data[idx].to_bytes_be();
        bytes.extend_from_slice(&word_bytes[1..]);
        idx += 1;
    }

    if idx + 1 >= data.len() {
        return Err(StarknetBridgeClientError::BlockchainDataError(
            "ByteArray decode: missing pending word or length".to_string(),
        ));
    }

    let pending_word = data[idx];
    let pending_len = felt_to_u64(data[idx + 1])? as usize;
    idx += 2;

    if pending_len > 0 {
        let pw_bytes = pending_word.to_bytes_be();
        let start = 32 - pending_len;
        bytes.extend_from_slice(&pw_bytes[start..]);
    }

    let s = String::from_utf8(bytes).map_err(|e| {
        StarknetBridgeClientError::BlockchainDataError(format!(
            "ByteArray decode: invalid UTF-8: {e}"
        ))
    })?;

    Ok((s, idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_u128_roundtrip() {
        let value: u128 = 123_456_789_012_345;
        let felt = StarknetBridgeClient::encode_u128(value);
        let back = felt_to_u128(felt).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn test_encode_u64_roundtrip() {
        let value: u64 = 9_876_543_210;
        let felt = StarknetBridgeClient::encode_u64(value);
        let back = felt_to_u64(felt).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn test_encode_u256_split() {
        // Build a 32-byte value where the first 16 bytes (high) = 1 and last 16 bytes (low) = 2
        let mut input = [0u8; 32];
        input[15] = 1; // high = 1
        input[31] = 2; // low = 2

        let [low, high] = StarknetBridgeClient::encode_u256(input);
        assert_eq!(felt_to_u128(low).unwrap(), 2);
        assert_eq!(felt_to_u128(high).unwrap(), 1);
    }

    #[test]
    fn test_encode_decode_byte_array_empty() {
        let encoded = StarknetBridgeClient::encode_byte_array("");
        let (decoded, next) = decode_byte_array(&encoded, 0).unwrap();
        assert_eq!(decoded, "");
        assert_eq!(next, encoded.len());
    }

    #[test]
    fn test_encode_decode_byte_array_short() {
        let input = "hello";
        let encoded = StarknetBridgeClient::encode_byte_array(input);
        let (decoded, next) = decode_byte_array(&encoded, 0).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(next, encoded.len());
    }

    #[test]
    fn test_encode_decode_byte_array_exact_31() {
        let input = "abcdefghijklmnopqrstuvwxyz01234"; // exactly 31 bytes
        assert_eq!(input.len(), 31);
        let encoded = StarknetBridgeClient::encode_byte_array(input);
        let (decoded, next) = decode_byte_array(&encoded, 0).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(next, encoded.len());
    }

    #[test]
    fn test_encode_decode_byte_array_multi_word() {
        let input = "This string is longer than thirty-one bytes for sure!!"; // > 31 bytes
        assert!(input.len() > 31);
        let encoded = StarknetBridgeClient::encode_byte_array(input);
        let (decoded, next) = decode_byte_array(&encoded, 0).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(next, encoded.len());
    }

    #[test]
    fn test_encode_signature() {
        let mut sig = [0u8; 65];
        // r = first 32 bytes, s = next 32 bytes, v = last byte
        sig[31] = 0xFF; // r low byte
        sig[63] = 0xAA; // s low byte
        sig[64] = 27; // v

        let felts = StarknetBridgeClient::encode_signature(&sig);
        assert_eq!(felts.len(), 5); // r_low, r_high, s_low, s_high, v

        // r_low should contain 0xFF
        assert_eq!(felt_to_u128(felts[0]).unwrap(), 0xFF);
        // r_high should be 0
        assert_eq!(felt_to_u128(felts[1]).unwrap(), 0);
        // s_low should contain 0xAA
        assert_eq!(felt_to_u128(felts[2]).unwrap(), 0xAA);
        // s_high should be 0
        assert_eq!(felt_to_u128(felts[3]).unwrap(), 0);
        // v should be 27
        assert_eq!(felt_to_u64(felts[4]).unwrap(), 27);
    }
}
