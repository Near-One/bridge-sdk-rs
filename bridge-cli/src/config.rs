use std::{fs::File, io::BufReader};

use clap::ValueEnum;

use crate::defaults;

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl From<Network> for utxo_utils::address::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => utxo_utils::address::Network::Mainnet,
            Network::Testnet | Network::Devnet => utxo_utils::address::Network::Testnet,
        }
    }
}

/// Declares every override once; generates the clap/serde struct, the layered
/// `or()` merge, and the `entries()` listing used by `bridge-cli config`.
///
/// Overrides are resolved as: CLI flag > env var > config file > per-network
/// default. The flags are hidden from help output (there are ~70 of them);
/// `bridge-cli config vars` lists them all.
macro_rules! cli_config {
    ($($field:ident: $ty:ty = $env:literal),* $(,)?) => {
        #[derive(clap::Args, Debug, Clone, Default, serde::Deserialize)]
        pub struct CliConfig {
            $(
                #[arg(long, global = true, hide = true, env = $env)]
                #[serde(default)]
                pub $field: Option<$ty>,
            )*
        }

        impl CliConfig {
            #[must_use]
            pub fn or(self, other: Self) -> Self {
                Self {
                    $($field: self.$field.or(other.$field)),*
                }
            }

            /// `(flag, env var, value)` for every override, in declaration order.
            pub fn entries(&self) -> Vec<(String, &'static str, Option<String>)> {
                vec![
                    $((
                        format!("--{}", stringify!($field).replace('_', "-")),
                        $env,
                        self.$field.as_ref().map(ToString::to_string),
                    )),*
                ]
            }
        }
    };
}

cli_config! {
    near_rpc: String = "NEAR_RPC",
    near_signer: String = "NEAR_SIGNER",
    near_private_key: String = "NEAR_PRIVATE_KEY",
    near_public_key: String = "NEAR_PUBLIC_KEY",
    near_token_locker_id: String = "TOKEN_LOCKER_ID",
    near_mpc_omni_prover_id: String = "MPC_OMNI_PROVER_ID",
    eth_light_client_id: String = "ETH_LIGHT_CLIENT_ID",
    btc_light_client_id: String = "BTC_LIGHT_CLIENT_ID",
    zcash_light_client_id: String = "ZCASH_LIGHT_CLIENT_ID",
    bridge_indexer_api_url: String = "BRIDGE_INDEXER_API_URL",

    eth_rpc: String = "ETH_RPC",
    eth_private_key: String = "ETH_PRIVATE_KEY",
    eth_bridge_token_factory_address: String = "ETH_BRIDGE_TOKEN_FACTORY_ADDRESS",

    base_rpc: String = "BASE_RPC",
    base_private_key: String = "BASE_PRIVATE_KEY",
    base_bridge_token_factory_address: String = "BASE_BRIDGE_TOKEN_FACTORY_ADDRESS",
    base_wormhole_address: String = "BASE_WORMHOLE_ADDRESS",

    arb_rpc: String = "ARB_RPC",
    arb_private_key: String = "ARB_PRIVATE_KEY",
    arb_bridge_token_factory_address: String = "ARB_BRIDGE_TOKEN_FACTORY_ADDRESS",
    arb_wormhole_address: String = "ARB_WORMHOLE_ADDRESS",

    bnb_rpc: String = "BNB_RPC",
    bnb_private_key: String = "BNB_PRIVATE_KEY",
    bnb_bridge_token_factory_address: String = "BNB_BRIDGE_TOKEN_FACTORY_ADDRESS",
    bnb_wormhole_address: String = "BNB_WORMHOLE_ADDRESS",

    pol_rpc: String = "POL_RPC",
    pol_private_key: String = "POL_PRIVATE_KEY",
    pol_bridge_token_factory_address: String = "POL_BRIDGE_TOKEN_FACTORY_ADDRESS",
    pol_wormhole_address: String = "POL_WORMHOLE_ADDRESS",

    hyperevm_rpc: String = "HYPEREVM_RPC",
    hyperevm_private_key: String = "HYPEREVM_PRIVATE_KEY",
    hyperevm_bridge_token_factory_address: String = "HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS",
    hyperevm_wormhole_address: String = "HYPEREVM_WORMHOLE_ADDRESS",

    hypercore_api: String = "HYPERCORE_API",
    hypercore_signature_chain_id: String = "HYPERCORE_SIGNATURE_CHAIN_ID",

    abs_rpc: String = "ABS_RPC",
    abs_private_key: String = "ABS_PRIVATE_KEY",
    abs_bridge_token_factory_address: String = "ABS_BRIDGE_TOKEN_FACTORY_ADDRESS",

    solana_rpc: String = "SOLANA_RPC",
    solana_bridge_address: String = "SOLANA_BRIDGE_ADDRESS",
    solana_wormhole_address: String = "SOLANA_WORMHOLE_ADDRESS",
    solana_wormhole_post_message_shim_program_id: String = "SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID",
    solana_keypair: String = "SOLANA_KEYPAIR",
    solana_public_key: String = "SOLANA_PUBLIC_KEY",

    fogo_rpc: String = "FOGO_RPC",
    fogo_bridge_address: String = "FOGO_BRIDGE_ADDRESS",
    fogo_wormhole_address: String = "FOGO_WORMHOLE_ADDRESS",
    fogo_wormhole_post_message_shim_program_id: String = "FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID",
    fogo_keypair: String = "FOGO_KEYPAIR",
    fogo_public_key: String = "FOGO_PUBLIC_KEY",

    wormhole_api: String = "WORMHOLE_API",

    btc_endpoint: String = "BTC_ENDPOINT",
    btc_api_key: String = "BTC_API_KEY",
    btc_basic_auth: String = "BTC_BASIC_AUTH",
    btc_connector: String = "BTC_CONNECTOR",
    btc: String = "BTC",
    satoshi_relayer: String = "SATOSHI_RELAYER",

    zcash_endpoint: String = "ZCASH_ENDPOINT",
    zcash_api_key: String = "ZCASH_API_KEY",
    zcash_basic_auth: String = "ZCASH_BASIC_AUTH",
    zcash_connector: String = "ZCASH_CONNECTOR",
    zcash: String = "ZCASH",
    enable_orchard: bool = "ENABLE_ORCHARD",

    starknet_rpc: String = "STARKNET_RPC",
    starknet_private_key: String = "STARKNET_PRIVATE_KEY",
    starknet_account_address: String = "STARKNET_ACCOUNT_ADDRESS",
    starknet_bridge_address: String = "STARKNET_BRIDGE_ADDRESS",
    starknet_chain_id: String = "STARKNET_CHAIN_ID",

    aptos_rpc: String = "APTOS_RPC",
    aptos_private_key: String = "APTOS_PRIVATE_KEY",
    aptos_account_address: String = "APTOS_ACCOUNT_ADDRESS",
    aptos_bridge_address: String = "APTOS_BRIDGE_ADDRESS",
}

/// Builds a `CliConfig` from one of the `defaults::{mainnet,testnet,devnet}`
/// modules. Fields without a network default (signers, private keys, API
/// credentials) fall through to `Default::default()`.
macro_rules! network_defaults {
    ($net:ident) => {{
        use defaults::$net as d;
        fn s(v: &str) -> Option<String> {
            Some(v.to_owned())
        }
        CliConfig {
            near_rpc: s(d::NEAR_RPC),
            near_token_locker_id: s(d::NEAR_TOKEN_LOCKER_ID),
            near_mpc_omni_prover_id: s(d::NEAR_MPC_OMNI_PROVER_ID),
            bridge_indexer_api_url: s(d::BRIDGE_INDEXER_API),
            eth_light_client_id: s(d::ETH_LIGHT_CLIENT_ID),
            btc_light_client_id: s(d::BTC_LIGHT_CLIENT_ID),
            zcash_light_client_id: s(d::ZCASH_LIGHT_CLIENT_ID),

            eth_rpc: s(d::ETH_RPC),
            eth_bridge_token_factory_address: s(d::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS),

            base_rpc: s(d::BASE_RPC),
            base_bridge_token_factory_address: s(d::BASE_BRIDGE_TOKEN_FACTORY_ADDRESS),
            base_wormhole_address: s(d::BASE_WORMHOLE_ADDRESS),

            arb_rpc: s(d::ARB_RPC),
            arb_bridge_token_factory_address: s(d::ARB_BRIDGE_TOKEN_FACTORY_ADDRESS),
            arb_wormhole_address: s(d::ARB_WORMHOLE_ADDRESS),

            bnb_rpc: s(d::BNB_RPC),
            bnb_bridge_token_factory_address: s(d::BNB_BRIDGE_TOKEN_FACTORY_ADDRESS),
            bnb_wormhole_address: s(d::BNB_WORMHOLE_ADDRESS),

            pol_rpc: s(d::POL_RPC),
            pol_bridge_token_factory_address: s(d::POL_BRIDGE_TOKEN_FACTORY_ADDRESS),
            pol_wormhole_address: s(d::POL_WORMHOLE_ADDRESS),

            hyperevm_rpc: s(d::HYPEREVM_RPC),
            hyperevm_bridge_token_factory_address: s(d::HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS),
            hyperevm_wormhole_address: s(d::HYPEREVM_WORMHOLE_ADDRESS),

            hypercore_api: s(d::HYPERCORE_API),
            hypercore_signature_chain_id: s(d::HYPERCORE_SIGNATURE_CHAIN_ID),

            abs_rpc: s(d::ABS_RPC),
            abs_bridge_token_factory_address: s(d::ABS_BRIDGE_TOKEN_FACTORY_ADDRESS),

            solana_rpc: s(d::SOLANA_RPC),
            solana_bridge_address: s(d::SOLANA_BRIDGE_ADDRESS),
            solana_wormhole_address: s(d::SOLANA_WORMHOLE_ADDRESS),
            solana_wormhole_post_message_shim_program_id: s(
                d::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID,
            ),

            fogo_rpc: s(d::FOGO_RPC),
            fogo_bridge_address: d::FOGO_BRIDGE_ADDRESS.map(str::to_owned),
            fogo_wormhole_address: s(d::FOGO_WORMHOLE_ADDRESS),
            fogo_wormhole_post_message_shim_program_id: s(
                d::FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID,
            ),

            wormhole_api: s(d::WORMHOLE_API),

            btc_endpoint: s(d::BTC_ENDPOINT),
            btc_connector: s(d::BTC_CONNECTOR),
            btc: s(d::BTC_TOKEN),
            satoshi_relayer: s(d::SATOSHI_RELAYER),

            zcash_endpoint: s(d::ZCASH_ENDPOINT),
            zcash_connector: s(d::ZCASH_CONNECTOR),
            zcash: s(d::ZCASH_TOKEN),
            enable_orchard: Some(d::ENABLE_ORCHARD_BUNDLE),

            starknet_rpc: s(d::STARKNET_RPC),
            starknet_bridge_address: s(d::STARKNET_BRIDGE_ADDRESS),
            starknet_chain_id: s(d::STARKNET_CHAIN_ID),

            aptos_rpc: s(d::APTOS_RPC),
            aptos_bridge_address: s(d::APTOS_BRIDGE_ADDRESS),

            ..Default::default()
        }
    }};
}

fn default_config(network: Network) -> CliConfig {
    match network {
        Network::Mainnet => network_defaults!(mainnet),
        Network::Testnet => network_defaults!(testnet),
        Network::Devnet => network_defaults!(devnet),
    }
}

fn file_config(path: &str) -> CliConfig {
    let file =
        File::open(path).unwrap_or_else(|err| panic!("Unable to open config file '{path}': {err}"));
    let reader = BufReader::new(file);

    serde_json::from_reader(reader)
        .unwrap_or_else(|err| panic!("Unable to parse config file '{path}': {err}"))
}

/// CLI flags and env vars are already merged by clap (flag wins); layer the
/// optional config file and the per-network defaults underneath.
pub fn resolve(cli: CliConfig, config_path: Option<&str>, network: Network) -> CliConfig {
    let file = config_path.map_or_else(CliConfig::default, file_config);
    cli.or(file).or(default_config(network))
}
