use base64::prelude::*;
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::{
    methods,
    methods::{block, broadcast_tx_commit, query},
    JsonRpcClient,
};
use near_jsonrpc_primitives::types::query::QueryResponseKind as RpcQueryResponseKind;
use near_primitives::{
    hash::CryptoHash,
    transaction::{Action, FunctionCallAction, SignedTransaction, Transaction, TransactionV0},
    types::{AccountId, BlockReference, Finality},
    views::QueryRequest,
};
use serde::{Deserialize, Serialize};
use solana_client::{rpc_client::RpcClient, rpc_config::RpcTransactionConfig};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedTransactionWithStatusMeta, UiTransactionEncoding,
    UiTransactionTokenBalance,
};
use std::env;
use std::str::FromStr;
use thiserror::Error;

/// POC configuration (dev/test only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PocConfig {
    pub verifier_account: AccountId,
    pub near_rpc: String,
    pub solana_rpc: String,
    pub bond_yocto: u128,
    pub challenge_period_secs: u64,
}

/// Simple signer for POC (do not use in production).
#[derive(Clone, Debug)]
pub struct PocSigner {
    pub account_id: AccountId,
    pub secret_key: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaProof {
    pub tx_sig: String,
    pub slot: u64,
    pub log_index: u64,
    /// Base64-encoded borsh payload {amount:u64, recipient:Vec<u8>, nonce:u64}
    pub message_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    pub amount: u64,
    pub recipient: AccountId,
    pub nonce: u64,
    pub proof: SolanaProof,
}

pub struct SolanaOptimisticPocClient {
    pub config: PocConfig,
    #[allow(dead_code)]
    near_client: JsonRpcClient,
}

impl SolanaOptimisticPocClient {
    pub fn new(config: PocConfig) -> Self {
        let near_client = JsonRpcClient::connect(&config.near_rpc);
        Self {
            config,
            near_client,
        }
    }

    pub fn compute_transfer_id(claim: &Claim) -> String {
        format!(
            "{}:{}:{}",
            claim.proof.tx_sig, claim.proof.log_index, claim.nonce
        )
    }

    /// Placeholder: submit optimistic init to NEAR POC contract.
    pub async fn init_claim(&self, signer: &PocSigner, claim: &Claim) -> Result<String, PocError> {
        self.verify_proof_on_solana(&claim.proof)?;
        let args = serde_json::to_vec(claim).map_err(|e| PocError::Other(e.to_string()))?;
        self.call_contract(signer, "init", args, self.config.bond_yocto, GAS_FOR_CALL)
            .await?;
        Ok(Self::compute_transfer_id(claim))
    }

    /// Placeholder: submit challenge to NEAR POC contract.
    pub async fn challenge(
        &self,
        signer: &PocSigner,
        transfer_id: &str,
        correct_message_base64: &str,
    ) -> Result<(), PocError> {
        let input = serde_json::json!({
            "transfer_id": transfer_id,
            "correct_message_bytes": BASE64_STANDARD.decode(correct_message_base64).map_err(|_| PocError::InvalidBase64)?,
        });
        let args = serde_json::to_vec(&input).map_err(|e| PocError::Other(e.to_string()))?;
        self.call_contract(signer, "challenge", args, 0, GAS_FOR_CALL)
            .await
    }

    /// Placeholder: finalize after challenge window.
    pub async fn finalize(&self, signer: &PocSigner, transfer_id: &str) -> Result<(), PocError> {
        let input = serde_json::json!({ "transfer_id": transfer_id });
        let args = serde_json::to_vec(&input).map_err(|e| PocError::Other(e.to_string()))?;
        self.call_contract(signer, "finalize", args, 0, GAS_FOR_CALL)
            .await
    }

    async fn call_contract(
        &self,
        signer: &PocSigner,
        method: &str,
        args: Vec<u8>,
        deposit: u128,
        gas: u64,
    ) -> Result<(), PocError> {
        let signer_id = signer.account_id.clone();
        let in_mem_signer =
            InMemorySigner::from_secret_key(signer_id.clone(), signer.secret_key.clone());
        let public_key = in_mem_signer.public_key();

        // Fetch access key for nonce
        let access_key: methods::query::RpcQueryResponse = self
            .near_client
            .call(query::RpcQueryRequest {
                block_reference: BlockReference::Finality(Finality::Final),
                request: QueryRequest::ViewAccessKey {
                    account_id: signer_id.clone(),
                    public_key: public_key.clone(),
                },
            })
            .await
            .map_err(|e| PocError::Rpc(e.to_string()))?;
        let current_nonce = match access_key.kind {
            RpcQueryResponseKind::AccessKey(view) => view.nonce,
            _ => return Err(PocError::Other("unexpected query response".into())),
        };

        // Fetch latest block hash
        let block: block::RpcBlockResponse = self
            .near_client
            .call(block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .map_err(|e| PocError::Rpc(e.to_string()))?;
        let block_hash: CryptoHash = block.header.hash;

        // Use a recent nonce; if tx fails due to nonce, retry with refreshed nonce.
        let mut nonce = current_nonce + 1;
        for attempt in 0..3 {
            let tx = Transaction::V0(TransactionV0 {
                signer_id: signer_id.clone(),
                public_key: public_key.clone(),
                nonce,
                receiver_id: self.config.verifier_account.clone(),
                block_hash,
                actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                    method_name: method.to_string(),
                    args: args.clone(),
                    gas,
                    deposit,
                }))],
            });
            let (hash, _) = tx.get_hash_and_size();
            let signature = in_mem_signer.sign(hash.as_ref());
            let signed = SignedTransaction::new(signature, tx);

            let res: Result<broadcast_tx_commit::RpcBroadcastTxCommitResponse, _> = self
                .near_client
                .call(broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                    signed_transaction: signed,
                })
                .await;
            match res {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("InvalidNonce") && attempt < 2 {
                        // refresh nonce and retry
                        let access_key: methods::query::RpcQueryResponse = self
                            .near_client
                            .call(query::RpcQueryRequest {
                                block_reference: BlockReference::Finality(Finality::Final),
                                request: QueryRequest::ViewAccessKey {
                                    account_id: signer_id.clone(),
                                    public_key: public_key.clone(),
                                },
                            })
                            .await
                            .map_err(|e| PocError::Rpc(e.to_string()))?;
                        nonce = match access_key.kind {
                            RpcQueryResponseKind::AccessKey(view) => view.nonce + 1,
                            _ => return Err(PocError::Other("unexpected query response".into())),
                        };
                        continue;
                    } else {
                        return Err(PocError::Rpc(msg));
                    }
                }
            }
        }
        Err(PocError::Rpc("nonce retries exhausted".into()))
    }

    fn verify_proof_on_solana(&self, proof: &SolanaProof) -> Result<(), PocError> {
        let sig = Signature::from_str(&proof.tx_sig)
            .map_err(|e| PocError::InvalidSignature(e.to_string()))?;
        let _program_id = Pubkey::from_str(DEFAULT_EMITTER_PROGRAM_ID)
            .map_err(|e| PocError::Other(e.to_string()))?;
        let rpc = RpcClient::new_with_commitment(
            self.config.solana_rpc.clone(),
            CommitmentConfig::confirmed(),
        );
        let tx = rpc
            .get_transaction_with_config(
                &sig,
                RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    max_supported_transaction_version: Some(0),
                    ..RpcTransactionConfig::default()
                },
            )
            .map_err(|e| PocError::SolanaRpc(e.to_string()))?;
        let EncodedTransactionWithStatusMeta { meta, .. } = tx.transaction;
        let meta = meta.ok_or_else(|| PocError::ProofMismatch("missing meta".into()))?;
        let logs = meta
            .log_messages
            .ok_or_else(|| PocError::ProofMismatch("no log messages".into()))?;
        let idx = proof.log_index as usize;
        if idx >= logs.len() {
            return Err(PocError::ProofMismatch("log_index out of bounds".into()));
        }
        let log_line = &logs[idx];
        if !log_line.starts_with(PROGRAM_LOG_PREFIX) {
            return Err(PocError::ProofMismatch(
                "expected Program log at log_index".into(),
            ));
        }
        let logged = log_line.trim_start_matches(PROGRAM_LOG_PREFIX);
        let logged_payload = if let Some(stripped) = logged.strip_prefix(LOG_EMIT_PREFIX) {
            stripped.trim()
        } else {
            logged.trim()
        };
        if logged_payload != proof.message_base64 {
            return Err(PocError::ProofMismatch("base64 payload mismatch".into()));
        }
        // Enforce SPL escrow balance increase and PDA presence by default.
        let (expected_pda, expected_mint, enforce_pda) = escrow_config()?;
        let mint = expected_mint.ok_or_else(|| PocError::ProofMismatch("escrow mint not configured".into()))?;
        let owner = expected_pda
            .ok_or_else(|| PocError::ProofMismatch("escrow PDA not configured".into()))?;
        if let Some(decoded_tx) = tx.transaction.transaction.decode() {
            let accounts = decoded_tx.message.static_account_keys();
            if enforce_pda && !accounts.iter().any(|k| k == &owner) {
                return Err(PocError::ProofMismatch(
                    "escrow PDA not present in account keys".into(),
                ));
            }
        }
        let post = token_balance_for(&meta.post_token_balances, &owner, &mint)?
            .ok_or_else(|| PocError::ProofMismatch("missing post balance for escrow PDA".into()))?;
        let pre = token_balance_for(&meta.pre_token_balances, &owner, &mint)?.unwrap_or(0);
        if post <= pre {
            return Err(PocError::ProofMismatch(
                "escrow balance did not increase".into(),
            ));
        }
        if tx.slot != proof.slot {
            return Err(PocError::ProofMismatch("slot mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum PocError {
    #[error("invalid base64 payload")]
    InvalidBase64,
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("solana rpc error: {0}")]
    SolanaRpc(String),
    #[error("proof mismatch: {0}")]
    ProofMismatch(String),
    #[error("other: {0}")]
    Other(String),
}

/// Simple helper to decode the base64 message for validation/logging.
pub fn decode_message_base64(message_base64: &str) -> Result<Vec<u8>, PocError> {
    BASE64_STANDARD
        .decode(message_base64)
        .map_err(|_| PocError::InvalidBase64)
}

const GAS_FOR_CALL: u64 = 300_000_000_000_000;
const DEFAULT_EMITTER_PROGRAM_ID: &str = "736wDEshwzrD18KrN7iqBAW9uPbNNVCKpQoJf8de3PF7";
const PROGRAM_LOG_PREFIX: &str = "Program log: ";
const LOG_EMIT_PREFIX: &str = "LOG_EMIT_BASE64 ";
const ENFORCE_ESCROW_PDA: bool = true;
const ESCROW_PDA_SEEDS: &[&[u8]] = &[b"escrow", b"wsol"];
const DEFAULT_ESCROW_MINT: &str = "So11111111111111111111111111111111111111112";

fn escrow_config() -> Result<(Option<Pubkey>, Option<String>, bool), PocError> {
    let env_pda = match env::var("POC_ESCROW_PDA") {
        Ok(val) => Some(Pubkey::from_str(&val).map_err(|e| PocError::Other(e.to_string()))?),
        Err(_) => None,
    };
    let env_mint = env::var("POC_ESCROW_MINT").ok();
    let enforce_env = matches!(
        env::var("POC_ENFORCE_ESCROW").as_deref(),
        Ok("1") | Ok("true") | Ok("True")
    );

    let fallback_pda = if ESCROW_PDA_SEEDS.is_empty() {
        None
    } else {
        let program_id = Pubkey::from_str(DEFAULT_EMITTER_PROGRAM_ID)
            .map_err(|e| PocError::Other(e.to_string()))?;
        let (pda, _) = Pubkey::find_program_address(ESCROW_PDA_SEEDS, &program_id);
        Some(pda)
    };

    let expected = env_pda.or(fallback_pda);
    let expected_mint = env_mint.or_else(|| Some(DEFAULT_ESCROW_MINT.to_string()));
    let enforce = enforce_env || ENFORCE_ESCROW_PDA || env_pda.is_some() || expected_mint.is_some();
    Ok((expected, expected_mint, enforce))
}

fn token_balance_for(
    balances: &OptionSerializer<Vec<UiTransactionTokenBalance>>,
    owner: &Pubkey,
    mint: &str,
) -> Result<Option<u64>, PocError> {
    let opt: Option<Vec<UiTransactionTokenBalance>> = balances.clone().into();
    let maybe = opt.as_ref().and_then(|vec| {
        vec.iter().find(|bal| {
            bal.mint == mint
                && bal
                    .owner
                    .as_ref()
                    .map(|o| o == &owner.to_string())
                    .unwrap_or(false)
        })
    });
    if let Some(balance) = maybe {
        parse_ui_amount(&balance.ui_token_amount.amount).map(Some)
    } else {
        Ok(None)
    }
}

fn parse_ui_amount(amount_str: &str) -> Result<u64, PocError> {
    amount_str
        .parse::<u64>()
        .map_err(|e| PocError::Other(format!("invalid token amount '{}': {}", amount_str, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_claim() -> Claim {
        Claim {
            amount: 1234,
            recipient: "user.testnet".parse().unwrap(),
            nonce: 1_764_346_052_217,
            proof: SolanaProof {
                tx_sig: "4FppEWschU2F5TLJHCy9Ctyhhy7TTDaeoV5DNC72YcUyeJNrs6zsNc1B5Zq8WbAMUsCmKPtpReZwbyhCEb7951UF".into(),
                slot: 424_660_806,
                log_index: 2,
                message_base64: "0gQAAAAAAAAMAAAAdXNlci50ZXN0bmV0eT44y5oBAAA=".into(),
            },
        }
    }

    #[test]
    fn transfer_id_matches_fixture() {
        let claim = fixture_claim();
        let id = SolanaOptimisticPocClient::compute_transfer_id(&claim);
        assert_eq!(id, "4FppEWschU2F5TLJHCy9Ctyhhy7TTDaeoV5DNC72YcUyeJNrs6zsNc1B5Zq8WbAMUsCmKPtpReZwbyhCEb7951UF:2:1764346052217");
    }

    #[test]
    fn decode_fixture_payload() {
        let claim = fixture_claim();
        let decoded = decode_message_base64(&claim.proof.message_base64).unwrap();
        // amount (u64), recipient len (u32), recipient bytes, nonce (u64)
        assert_eq!(decoded.len(), 8 + 4 + "user.testnet".len() + 8);
    }
}
