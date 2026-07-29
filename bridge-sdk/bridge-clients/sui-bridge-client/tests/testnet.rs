//! Network tests against the Sui testnet deployment from
//! Near-One/omni-bridge#633 (test MPC key — not production). Run manually:
//!
//! ```sh
//! cargo test -p sui-bridge-client -- --ignored --nocapture
//! ```

use sui_bridge_client::error::SuiBridgeClientError;
use sui_bridge_client::{bytecode, token_address_from_coin_type, SuiBridgeClientBuilder};

/// Package / state ids of the testnet deployment, and the example
/// `init_transfer` from the PR description (0.001 SUI -> near:frolik.testnet).
const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io";
/// Fullnodes prune history; the example transaction is only on the archive.
const TESTNET_ARCHIVE_RPC: &str = "https://archive.testnet.sui.io";
const TESTNET_BRIDGE: &str = "0x587d69879cb01f62a88526a7448424c37cf767387473c1e610bd007dc95fa6ba";
const TESTNET_STATE: &str = "0xcbe9d3824224eaa23e2ef70667fff857ddd0929b7c0e42935d509347505fe858";
const EXAMPLE_INIT_TRANSFER_TX: &str = "HcrYCissQ4qS1bF5DXa5zmejYiHVwupPWMuq1t9eYiot";

fn client_for(endpoint: &str) -> sui_bridge_client::SuiBridgeClient {
    SuiBridgeClientBuilder::default()
        .endpoint(Some(endpoint.to_string()))
        .bridge_address(Some(TESTNET_BRIDGE.to_string()))
        .state_object_id(Some(TESTNET_STATE.to_string()))
        .mpc_finality(Some(
            near_mpc_contract_interface::types::SuiFinality::Checkpointed,
        ))
        .build()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires network access to Sui testnet"]
async fn reads_init_transfer_event_log_from_known_tx() {
    let client = client_for(TESTNET_ARCHIVE_RPC);

    let log = client
        .get_init_transfer_log(EXAMPLE_INIT_TRANSFER_TX)
        .await
        .unwrap();
    // Canonical long-form type tag with the defining package id.
    assert_eq!(
        log.type_tag,
        format!("{TESTNET_BRIDGE}::omni_bridge::InitTransfer")
    );
    assert_eq!(log.transaction_module, "omni_bridge");
    assert!(!log.bcs.is_empty());

    let event = client
        .get_transfer_event(EXAMPLE_INIT_TRANSFER_TX)
        .await
        .unwrap();
    assert_eq!(event.recipient, "near:frolik.testnet");
    assert_eq!(event.amount, 1_000_000); // 0.001 SUI in MIST
    assert_eq!(
        event.token_address,
        token_address_from_coin_type("0x2::sui::SUI").unwrap()
    );
}

#[tokio::test]
#[ignore = "requires network access to Sui testnet"]
async fn check_mpc_finality_passes_for_checkpointed_tx() {
    let client = client_for(TESTNET_ARCHIVE_RPC);
    client
        .check_mpc_finality(EXAMPLE_INIT_TRANSFER_TX)
        .await
        .unwrap();
}

/// The Move bytecode verifier runs while a `Publish` command executes, so a
/// successful simulation is the node itself verifying the patched module —
/// no gas or signer needed. `PEPE`/`PEPE` is the case that produced duplicate
/// constant-pool entries (and a verifier rejection) before the combined
/// params constant.
#[tokio::test]
#[ignore = "requires network access to Sui testnet"]
async fn patched_template_publish_passes_move_verifier_in_simulation() {
    use sui_rpc::field::{FieldMask, FieldMaskUtil};
    use sui_rpc::proto::sui::rpc::v2::simulate_transaction_request::TransactionChecks;
    use sui_rpc::proto::sui::rpc::v2::SimulateTransactionRequest;
    use sui_sdk_types::{
        Address, Argument, Command, GasPayment, Input, ProgrammableTransaction, Publish,
        Transaction, TransactionExpiration, TransactionKind, TransferObjects,
    };

    for (symbol, name) in [("PEPE", "PEPE"), ("", "Wrapped Foo"), ("FOO", "")] {
        let (module_name, otw_name) = bytecode::coin_module_identifiers(symbol);
        let patched = bytecode::patch_token_template(
            bytecode::TOKEN_TEMPLATE_BYTECODE,
            &module_name,
            &otw_name,
            symbol,
            name,
            6,
        )
        .unwrap();

        let sender = Address::ZERO;
        let transaction = Transaction {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs: vec![Input::Pure(bcs::to_bytes(&sender).unwrap())],
                commands: vec![
                    Command::Publish(Publish {
                        modules: vec![patched],
                        dependencies: bytecode::TOKEN_TEMPLATE_DEPENDENCIES
                            .iter()
                            .map(|address| Address::new(*address))
                            .collect(),
                    }),
                    Command::TransferObjects(TransferObjects {
                        objects: vec![Argument::Result(0)],
                        address: Argument::Input(0),
                    }),
                ],
            }),
            sender,
            // Empty payment + non-zero price: the node synthesizes a mock
            // gas coin for the simulation (see `call_view`).
            gas_payment: GasPayment {
                objects: vec![],
                owner: sender,
                price: 1000,
                budget: 1_000_000_000,
            },
            expiration: TransactionExpiration::None,
        };

        let mut client = sui_rpc::Client::new(TESTNET_RPC).unwrap();
        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::default()
                    .with_transaction(transaction)
                    .with_checks(TransactionChecks::Disabled)
                    .with_read_mask(FieldMask::from_paths(["transaction.effects"])),
            )
            .await
            .unwrap()
            .into_inner();

        let status = response.transaction().effects().status();
        assert!(
            status.success(),
            "publish simulation for symbol={symbol:?} name={name:?} failed: {}",
            status.error()
        );
    }
}

#[tokio::test]
#[ignore = "requires network access to Sui testnet"]
async fn views_work_via_simulation() {
    let client = client_for(TESTNET_RPC);

    // A huge nonce has certainly not been finalised.
    let finalised = client.is_transfer_finalised(u64::MAX - 1).await.unwrap();
    assert!(!finalised);

    // Whether SUI is registered depends on the deployment's log_metadata
    // history — either outcome proves the on-chain view executed and decoded.
    match client
        .get_coin_type(token_address_from_coin_type("0x2::sui::SUI").unwrap())
        .await
    {
        Ok(coin_type) => assert!(coin_type.ends_with("::sui::SUI"), "got {coin_type}"),
        Err(SuiBridgeClientError::BlockchainDataError(msg)) => {
            assert!(msg.contains("not registered"), "unexpected error: {msg}");
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}
