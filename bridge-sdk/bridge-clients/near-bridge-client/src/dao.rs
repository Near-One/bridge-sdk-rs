use crate::{NearBridgeClient, TransactionOptions};
use bridge_connector_common::result::{BridgeSdkError, Result};
use near_primitives::views::FinalExecutionStatus;
use near_primitives::{hash::CryptoHash, types::AccountId};
use near_rpc_client::{ChangeRequest, ViewRequest};
use near_sdk::json_types::{Base64VecU8, U128, U64};
use omni_types::{locker_args::StorageDepositAction, prover_result::InitTransferMessage};

pub const FIN_TRANSFER_AS_DAO_METHOD: &str = "fin_transfer_as_dao";
pub const FIN_TRANSFER_AS_DAO_GAS: u64 = 300_000_000_000_000;

const ADD_PROPOSAL_GAS: u64 = 30_000_000_000_000;

/// Arguments of `OmniBridge::fin_transfer_as_dao`.
///
/// Serialize with `serde_json::to_vec`, not through `serde_json::Value`, which
/// cannot hold a `storage_deposit_amount` above `u64::MAX`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FinTransferAsDaoArgs {
    pub init_transfer: InitTransferMessage,
    pub storage_deposit_actions: Vec<StorageDepositAction>,
}

/// A function call of a Sputnik DAO `FunctionCall` proposal
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DaoActionCall {
    pub method_name: String,
    pub args: Base64VecU8,
    pub deposit: U128,
    pub gas: U64,
}

/// Sputnik DAO proposal kind. Only `FunctionCall` is modelled.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DaoProposalKind {
    FunctionCall {
        receiver_id: AccountId,
        actions: Vec<DaoActionCall>,
    },
}

/// Sputnik DAO proposal as returned by `get_proposal`. `kind` is kept as raw
/// JSON so proposals of any kind can be fetched.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DaoProposal {
    pub id: u64,
    pub proposer: AccountId,
    pub description: String,
    pub kind: serde_json::Value,
    pub status: String,
}

#[derive(serde::Deserialize)]
struct DaoPolicy {
    proposal_bond: U128,
}

impl NearBridgeClient {
    /// Whether `account_id` holds `role` in the `OmniBridge` access control list
    pub async fn acl_has_role(&self, role: &str, account_id: AccountId) -> Result<bool> {
        let endpoint = self.endpoint()?;
        let omni_bridge_id = self.omni_bridge_id()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: omni_bridge_id,
                method_name: "acl_has_role".to_string(),
                args: serde_json::json!({
                    "role": role,
                    "account_id": account_id,
                }),
            },
        )
        .await?;

        Ok(serde_json::from_slice::<bool>(&response)?)
    }

    /// Deposit the Sputnik DAO `dao_id` requires to add a proposal
    pub async fn dao_get_proposal_bond(&self, dao_id: AccountId) -> Result<u128> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: dao_id,
                method_name: "get_policy".to_string(),
                args: serde_json::json!({}),
            },
        )
        .await?;

        Ok(serde_json::from_slice::<DaoPolicy>(&response)?
            .proposal_bond
            .0)
    }

    pub async fn dao_get_proposal(
        &self,
        dao_id: AccountId,
        proposal_id: u64,
    ) -> Result<DaoProposal> {
        let endpoint = self.endpoint()?;

        let response = near_rpc_client::view(
            endpoint,
            ViewRequest {
                contract_account_id: dao_id,
                method_name: "get_proposal".to_string(),
                args: serde_json::json!({ "id": proposal_id }),
            },
        )
        .await?;

        Ok(serde_json::from_slice::<DaoProposal>(&response)?)
    }

    /// Adds a proposal to the Sputnik DAO `dao_id`, attaching `proposal_bond`.
    /// Returns the transaction hash and the id of the new proposal (`None` in dry-run).
    #[tracing::instrument(skip_all, name = "DAO ADD PROPOSAL")]
    pub async fn dao_add_proposal(
        &self,
        dao_id: AccountId,
        description: String,
        kind: DaoProposalKind,
        proposal_bond: u128,
        transaction_options: TransactionOptions,
    ) -> Result<(CryptoHash, Option<u64>)> {
        let endpoint = self.endpoint()?;
        let signer = self.signer()?;
        let is_dry_run = signer.is_dry_run();
        let signer_id = signer.account_id();

        let tx_hash = near_rpc_client::change_and_wait(
            endpoint,
            ChangeRequest {
                signer,
                nonce: transaction_options.nonce,
                receiver_id: dao_id,
                method_name: "add_proposal".to_string(),
                args: serde_json::json!({
                    "proposal": {
                        "description": description,
                        "kind": kind,
                    }
                })
                .to_string()
                .into_bytes(),
                gas: ADD_PROPOSAL_GAS,
                deposit: proposal_bond,
            },
            transaction_options.wait_until,
            transaction_options.wait_final_outcome_timeout_sec,
        )
        .await?;

        if is_dry_run {
            return Ok((tx_hash, None));
        }

        let outcome = near_rpc_client::get_tx_final_outcome(endpoint, tx_hash, signer_id).await?;
        let proposal_id = match outcome.status {
            FinalExecutionStatus::SuccessValue(value) => serde_json::from_slice::<u64>(&value)?,
            status => {
                return Err(BridgeSdkError::UnknownError(format!(
                    "add_proposal transaction {tx_hash} did not succeed: {status:?}"
                )))
            }
        };

        tracing::info!(
            tx_hash = tx_hash.to_string(),
            proposal_id,
            "Sent add proposal transaction"
        );
        Ok((tx_hash, Some(proposal_id)))
    }
}
