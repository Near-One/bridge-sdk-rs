//! Builds the `OmniConnector` from resolved configuration.

use std::collections::HashMap;
use std::path::Path;

use aptos_bridge_client::AptosBridgeClientBuilder;
use evm_bridge_client::EvmBridgeClientBuilder;
use hypercore_bridge_client::{HyperCoreBridgeClientBuilder, HyperliquidNetwork};
use light_client::LightClientBuilder;
use near_bridge_client::{NearBridgeClientBuilder, UTXOChainAccounts};
use near_mpc_contract_interface::types::{AptosFinality, EvmFinality, StarknetFinality};
use omni_connector::{OmniConnector, OmniConnectorBuilder};
use omni_types::ChainKind;
use solana_bridge_client::{SolanaBridgeClientBuilder, SvmSigner};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{signature::Keypair, signer::EncodableKey};
use starknet_bridge_client::StarknetBridgeClientBuilder;
use utxo_bridge_client::{
    types::{Bitcoin, Zcash},
    AuthOptions, UTXOBridgeClient,
};
use wormhole_bridge_client::WormholeBridgeClientBuilder;

use crate::commands::Ctx;
use crate::config::{CliConfig, Network};

pub fn extract_solana_keypair(keypair: &str) -> Keypair {
    if keypair.contains('/') || keypair.contains('.') {
        Keypair::read_from_file(Path::new(&keypair)).unwrap()
    } else {
        Keypair::from_base58_string(keypair)
    }
}

fn svm_signer_from_config(
    keypair: Option<&str>,
    public_key: Option<&str>,
    dry_run: bool,
) -> Option<SvmSigner> {
    if dry_run {
        public_key.map(|pk| {
            let pubkey = pk.parse().unwrap_or_else(|e| {
                eprintln!("error: invalid SVM public key ({pk}): {e}");
                std::process::exit(1);
            });
            SvmSigner::DryRun(pubkey)
        })
    } else {
        keypair.map(extract_solana_keypair).map(SvmSigner::Keypair)
    }
}

/// `--dry-run` builds and prints an unsigned transaction instead of
/// broadcasting. It is supported for transactions submitted to NEAR and to
/// SVM chains (Solana/Fogo) — the latter require the target chain's fee-payer
/// public key. Every command that broadcasts calls this with the chain it is
/// about to submit to, once that chain is resolved, so a stray `--dry-run`
/// never lets a transaction go out for real.
pub fn ensure_dry_run_allowed(ctx: &Ctx, target: ChainKind) {
    if !ctx.dry_run {
        return;
    }

    match target {
        ChainKind::Near => {}
        ChainKind::Sol | ChainKind::Fogo => {
            let (key, flag) = if target == ChainKind::Sol {
                (
                    &ctx.config.solana_public_key,
                    "--solana-public-key / SOLANA_PUBLIC_KEY",
                )
            } else {
                (
                    &ctx.config.fogo_public_key,
                    "--fogo-public-key / FOGO_PUBLIC_KEY",
                )
            };
            if key.is_none() {
                eprintln!(
                    "error: --dry-run for an SVM command requires the fee-payer public key ({flag})"
                );
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "error: --dry-run is not supported for transactions submitted to {target:?}; \
                 it would broadcast for real"
            );
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_lines)]
pub fn build(network: Network, config: &CliConfig, dry_run: bool) -> OmniConnector {
    let config: CliConfig = config.clone();

    let utxo_bridges = HashMap::from([
        (
            ChainKind::Zcash,
            UTXOChainAccounts {
                utxo_chain_connector: config
                    .zcash_connector
                    .map(|account| account.parse().unwrap()),
                utxo_chain_token: config.zcash.map(|account| account.parse().unwrap()),
                satoshi_relayer: None,
            },
        ),
        (
            ChainKind::Btc,
            UTXOChainAccounts {
                utxo_chain_connector: config.btc_connector.map(|account| account.parse().unwrap()),
                utxo_chain_token: config.btc.map(|account| account.parse().unwrap()),
                satoshi_relayer: config
                    .satoshi_relayer
                    .map(|account| account.parse().unwrap()),
            },
        ),
    ]);

    let near_bridge_client = NearBridgeClientBuilder::default()
        .endpoint(config.near_rpc.clone())
        .private_key(config.near_private_key)
        .signer(config.near_signer.map(|account| account.parse().unwrap()))
        .signer_public_key(config.near_public_key)
        .dry_run(dry_run)
        .omni_bridge_id(
            config
                .near_token_locker_id
                .map(|account| account.parse().unwrap()),
        )
        .mpc_omni_prover_id(
            config
                .near_mpc_omni_prover_id
                .map(|account| account.parse().unwrap()),
        )
        .utxo_bridges(utxo_bridges)
        .bridge_indexer_api_url(
            config
                .bridge_indexer_api_url
                .map(|url| url.parse().unwrap()),
        )
        .build()
        .unwrap();

    let eth_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.eth_rpc)
        .private_key(config.eth_private_key)
        .omni_bridge_address(config.eth_bridge_token_factory_address)
        .wormhole_core_address(None)
        .build()
        .unwrap();

    let base_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.base_rpc)
        .private_key(config.base_private_key)
        .omni_bridge_address(config.base_bridge_token_factory_address)
        .wormhole_core_address(config.base_wormhole_address)
        .build()
        .unwrap();

    let arb_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.arb_rpc)
        .private_key(config.arb_private_key)
        .omni_bridge_address(config.arb_bridge_token_factory_address)
        .wormhole_core_address(config.arb_wormhole_address)
        .build()
        .unwrap();

    let bnb_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.bnb_rpc)
        .private_key(config.bnb_private_key)
        .omni_bridge_address(config.bnb_bridge_token_factory_address)
        .wormhole_core_address(config.bnb_wormhole_address)
        .build()
        .unwrap();

    let pol_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.pol_rpc)
        .private_key(config.pol_private_key)
        .omni_bridge_address(config.pol_bridge_token_factory_address)
        .wormhole_core_address(config.pol_wormhole_address)
        .build()
        .unwrap();

    let hyperevm_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.hyperevm_rpc.clone())
        .private_key(config.hyperevm_private_key.clone())
        .omni_bridge_address(config.hyperevm_bridge_token_factory_address)
        .wormhole_core_address(config.hyperevm_wormhole_address)
        .build()
        .unwrap();

    let abs_bridge_client = EvmBridgeClientBuilder::default()
        .endpoint(config.abs_rpc)
        .private_key(config.abs_private_key)
        .omni_bridge_address(config.abs_bridge_token_factory_address)
        .wormhole_core_address(None)
        .mpc_finality(Some(EvmFinality::Latest))
        .build()
        .unwrap();

    let hypercore_network = match network {
        Network::Mainnet => HyperliquidNetwork::Mainnet,
        Network::Testnet | Network::Devnet => HyperliquidNetwork::Testnet,
    };
    let hypercore_bridge_client = config.hyperevm_private_key.as_ref().map(|pk| {
        HyperCoreBridgeClientBuilder::default()
            .network(hypercore_network)
            .api_url(config.hypercore_api.clone())
            .hyperevm_rpc_url(config.hyperevm_rpc.clone())
            .private_key(Some(pk.clone()))
            .signature_chain_id(config.hypercore_signature_chain_id.clone())
            .poll_interval(None)
            .poll_timeout(None)
            .build()
            .unwrap()
    });

    let solana_bridge_client = SolanaBridgeClientBuilder::default()
        .client(config.solana_rpc.map(RpcClient::new))
        .program_id(
            config
                .solana_bridge_address
                .map(|addr| addr.parse().unwrap()),
        )
        .wormhole_core(
            config
                .solana_wormhole_address
                .map(|addr| addr.parse().unwrap()),
        )
        .wormhole_post_message_shim_program_id(
            config
                .solana_wormhole_post_message_shim_program_id
                .map(|addr| addr.parse().unwrap()),
        )
        .signer(svm_signer_from_config(
            config.solana_keypair.as_deref(),
            config.solana_public_key.as_deref(),
            dry_run,
        ))
        .build()
        .unwrap();

    let fogo_bridge_client = SolanaBridgeClientBuilder::default()
        .client(config.fogo_rpc.map(RpcClient::new))
        .program_id(config.fogo_bridge_address.map(|addr| addr.parse().unwrap()))
        .wormhole_core(
            config
                .fogo_wormhole_address
                .map(|addr| addr.parse().unwrap()),
        )
        .wormhole_post_message_shim_program_id(
            config
                .fogo_wormhole_post_message_shim_program_id
                .map(|addr| addr.parse().unwrap()),
        )
        .signer(svm_signer_from_config(
            config.fogo_keypair.as_deref(),
            config.fogo_public_key.as_deref(),
            dry_run,
        ))
        .build()
        .unwrap();

    let wormhole_bridge_client = WormholeBridgeClientBuilder::default()
        .endpoint(config.wormhole_api)
        .build()
        .unwrap();

    let btc_client_auth = if let Some(api_key) = config.btc_api_key {
        AuthOptions::XApiKey(api_key)
    } else if let Some(basic_auth) = config.btc_basic_auth {
        let (user, password) = basic_auth.split_once(':').unwrap();
        AuthOptions::BasicAuth(user.to_string(), password.to_string())
    } else {
        AuthOptions::None
    };

    let zcash_client_auth = if let Some(api_key) = config.zcash_api_key {
        AuthOptions::XApiKey(api_key)
    } else if let Some(basic_auth) = config.zcash_basic_auth {
        let (user, password) = basic_auth.split_once(':').unwrap();
        AuthOptions::BasicAuth(user.to_string(), password.to_string())
    } else {
        AuthOptions::None
    };

    let btc_bridge_client =
        UTXOBridgeClient::<Bitcoin>::new(config.btc_endpoint.unwrap(), btc_client_auth);

    let zcash_bridge_client =
        UTXOBridgeClient::<Zcash>::new(config.zcash_endpoint.unwrap(), zcash_client_auth);

    let eth_light_client = LightClientBuilder::default()
        .endpoint(config.near_rpc.clone())
        .chain(Some(ChainKind::Eth))
        .light_client_id(
            config
                .eth_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    let btc_light_client = LightClientBuilder::default()
        .endpoint(config.near_rpc.clone())
        .chain(Some(ChainKind::Btc))
        .light_client_id(
            config
                .btc_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    let zcash_light_client = LightClientBuilder::default()
        .endpoint(config.near_rpc.clone())
        .chain(Some(ChainKind::Zcash))
        .light_client_id(
            config
                .zcash_light_client_id
                .map(|light_client| light_client.parse().unwrap()),
        )
        .build()
        .unwrap();

    let starknet_bridge_client = StarknetBridgeClientBuilder::default()
        .endpoint(config.starknet_rpc)
        .private_key(config.starknet_private_key)
        .account_address(config.starknet_account_address)
        .omni_bridge_address(config.starknet_bridge_address)
        .chain_id(config.starknet_chain_id)
        .mpc_finality(Some(StarknetFinality::AcceptedOnL2))
        .build()
        .unwrap();

    let aptos_bridge_client = AptosBridgeClientBuilder::default()
        .endpoint(config.aptos_rpc)
        .private_key(config.aptos_private_key)
        .account_address(config.aptos_account_address)
        .omni_bridge_address(config.aptos_bridge_address)
        .mpc_finality(Some(AptosFinality::Committed))
        .build()
        .unwrap();

    OmniConnectorBuilder::default()
        .network(Some(network.into()))
        .near_bridge_client(Some(near_bridge_client))
        .eth_bridge_client(Some(eth_bridge_client))
        .base_bridge_client(Some(base_bridge_client))
        .arb_bridge_client(Some(arb_bridge_client))
        .bnb_bridge_client(Some(bnb_bridge_client))
        .pol_bridge_client(Some(pol_bridge_client))
        .hyperevm_bridge_client(Some(hyperevm_bridge_client))
        .abs_bridge_client(Some(abs_bridge_client))
        .hypercore_bridge_client(hypercore_bridge_client)
        .solana_bridge_client(Some(solana_bridge_client))
        .fogo_bridge_client(Some(fogo_bridge_client))
        .starknet_bridge_client(Some(starknet_bridge_client))
        .aptos_bridge_client(Some(aptos_bridge_client))
        .wormhole_bridge_client(Some(wormhole_bridge_client))
        .btc_bridge_client(Some(btc_bridge_client))
        .zcash_bridge_client(Some(zcash_bridge_client))
        .eth_light_client(Some(eth_light_client))
        .btc_light_client(Some(btc_light_client))
        .zcash_light_client(Some(zcash_light_client))
        .enable_orchard(config.enable_orchard)
        .build()
        .unwrap()
}
