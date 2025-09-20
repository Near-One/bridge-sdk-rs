use clap::{Args, Parser, ValueEnum};
use omni_connector_command::OmniConnectorSubCommand;
use serde::Deserialize;
use std::{env, fs::File, io::BufReader};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{field::MakeExt, fmt::format, EnvFilter, FmtSubscriber};

mod defaults;
mod omni_connector_command;

#[derive(Args, Debug, Clone, Deserialize, Default)]
struct CliConfig {
    #[arg(long)]
    near_rpc: Option<String>,
    #[arg(long)]
    near_signer: Option<String>,
    #[arg(long)]
    near_private_key: Option<String>,
    #[arg(long)]
    near_token_locker_id: Option<String>,
    #[arg(long)]
    eth_light_client_id: Option<String>,
    #[arg(long)]
    btc_light_client_id: Option<String>,
    #[arg(long)]
    zcash_light_client_id: Option<String>,

    #[arg(long)]
    eth_rpc: Option<String>,
    #[arg(long)]
    eth_chain_id: Option<u64>,
    #[arg(long)]
    eth_private_key: Option<String>,
    #[arg(long)]
    eth_bridge_token_factory_address: Option<String>,

    #[arg(long)]
    base_rpc: Option<String>,
    #[arg(long)]
    base_chain_id: Option<u64>,
    #[arg(long)]
    base_private_key: Option<String>,
    #[arg(long)]
    base_bridge_token_factory_address: Option<String>,
    #[arg(long)]
    base_wormhole_address: Option<String>,

    #[arg(long)]
    arb_rpc: Option<String>,
    #[arg(long)]
    arb_chain_id: Option<u64>,
    #[arg(long)]
    arb_private_key: Option<String>,
    #[arg(long)]
    arb_bridge_token_factory_address: Option<String>,
    #[arg(long)]
    arb_wormhole_address: Option<String>,

    #[arg(long)]
    bnb_rpc: Option<String>,
    #[arg(long)]
    bnb_chain_id: Option<u64>,
    #[arg(long)]
    bnb_private_key: Option<String>,
    #[arg(long)]
    bnb_bridge_token_factory_address: Option<String>,
    #[arg(long)]
    bnb_wormhole_address: Option<String>,

    #[arg(long)]
    solana_rpc: Option<String>,
    #[arg(long)]
    solana_bridge_address: Option<String>,
    #[arg(long)]
    solana_wormhole_address: Option<String>,
    #[arg(long)]
    solana_wormhole_post_message_shim_program_id: Option<String>,
    #[arg(long)]
    solana_wormhole_post_message_shim_event_authority: Option<String>,
    #[arg(long)]
    solana_keypair: Option<String>,

    #[arg(long)]
    wormhole_api: Option<String>,

    #[arg(long)]
    btc_endpoint: Option<String>,
    #[arg(long)]
    btc_api_key: Option<String>,
    #[arg(long)]
    btc_basic_auth: Option<String>,
    #[arg(long)]
    btc_connector: Option<String>,
    #[arg(long)]
    btc: Option<String>,
    #[arg(long)]
    satoshi_relayer: Option<String>,

    #[arg(long)]
    zcash_endpoint: Option<String>,
    #[arg(long)]
    zcash_api_key: Option<String>,
    #[arg(long)]
    zcash_basic_auth: Option<String>,
    #[arg(long)]
    zcash_connector: Option<String>,
    #[arg(long)]
    zcash: Option<String>,

    #[arg(long)]
    config: Option<String>,
}

impl CliConfig {
    fn or(self, other: Self) -> Self {
        Self {
            near_rpc: self.near_rpc.or(other.near_rpc),
            near_signer: self.near_signer.or(other.near_signer),
            near_private_key: self.near_private_key.or(other.near_private_key),
            near_token_locker_id: self.near_token_locker_id.or(other.near_token_locker_id),
            eth_light_client_id: self.eth_light_client_id.or(other.eth_light_client_id),
            btc_light_client_id: self.btc_light_client_id.or(other.btc_light_client_id),
            zcash_light_client_id: self.zcash_light_client_id.or(other.zcash_light_client_id),

            eth_rpc: self.eth_rpc.or(other.eth_rpc),
            eth_chain_id: self.eth_chain_id.or(other.eth_chain_id),
            eth_private_key: self.eth_private_key.or(other.eth_private_key),
            eth_bridge_token_factory_address: self
                .eth_bridge_token_factory_address
                .or(other.eth_bridge_token_factory_address),

            base_rpc: self.base_rpc.or(other.base_rpc),
            base_chain_id: self.base_chain_id.or(other.base_chain_id),
            base_private_key: self.base_private_key.or(other.base_private_key),
            base_bridge_token_factory_address: self
                .base_bridge_token_factory_address
                .or(other.base_bridge_token_factory_address),
            base_wormhole_address: self.base_wormhole_address.or(other.base_wormhole_address),

            arb_rpc: self.arb_rpc.or(other.arb_rpc),
            arb_chain_id: self.arb_chain_id.or(other.arb_chain_id),
            arb_private_key: self.arb_private_key.or(other.arb_private_key),
            arb_bridge_token_factory_address: self
                .arb_bridge_token_factory_address
                .or(other.arb_bridge_token_factory_address),
            arb_wormhole_address: self.arb_wormhole_address.or(other.arb_wormhole_address),

            bnb_rpc: self.bnb_rpc.or(other.bnb_rpc),
            bnb_chain_id: self.bnb_chain_id.or(other.bnb_chain_id),
            bnb_private_key: self.bnb_private_key.or(other.bnb_private_key),
            bnb_bridge_token_factory_address: self
                .bnb_bridge_token_factory_address
                .or(other.bnb_bridge_token_factory_address),
            bnb_wormhole_address: self.bnb_wormhole_address.or(other.bnb_wormhole_address),

            solana_rpc: self.solana_rpc.or(other.solana_rpc),
            solana_bridge_address: self.solana_bridge_address.or(other.solana_bridge_address),
            solana_wormhole_address: self
                .solana_wormhole_address
                .or(other.solana_wormhole_address),
            solana_wormhole_post_message_shim_program_id: self
                .solana_wormhole_post_message_shim_program_id
                .or(other.solana_wormhole_post_message_shim_program_id),
            solana_wormhole_post_message_shim_event_authority: self
                .solana_wormhole_post_message_shim_event_authority
                .or(other.solana_wormhole_post_message_shim_event_authority),
            solana_keypair: self.solana_keypair.or(other.solana_keypair),

            wormhole_api: self.wormhole_api.or(other.wormhole_api),

            btc_endpoint: self.btc_endpoint.or(other.btc_endpoint),
            btc_api_key: self.btc_api_key.or(other.btc_api_key),
            btc_basic_auth: self.btc_basic_auth.or(other.btc_basic_auth),
            btc_connector: self.btc_connector.or(other.btc_connector),
            btc: self.btc.or(other.btc),
            satoshi_relayer: self.satoshi_relayer.or(other.satoshi_relayer),

            zcash_endpoint: self.zcash_endpoint.or(other.zcash_endpoint),
            zcash_api_key: self.zcash_api_key.or(other.zcash_api_key),
            zcash_basic_auth: self.zcash_basic_auth.or(other.zcash_basic_auth),
            zcash_connector: self.zcash_connector.or(other.zcash_connector),
            zcash: self.zcash.or(other.zcash),

            config: self.config.or(other.config),
        }
    }
}

fn env_config() -> CliConfig {
    CliConfig {
        near_rpc: env::var("NEAR_RPC").ok(),
        near_signer: env::var("NEAR_SIGNER").ok(),
        near_private_key: env::var("NEAR_PRIVATE_KEY").ok(),
        near_token_locker_id: env::var("TOKEN_LOCKER_ID").ok(),
        eth_light_client_id: env::var("ETH_LIGHT_CLIENT_ID").ok(),
        btc_light_client_id: env::var("BTC_LIGHT_CLIENT_ID").ok(),
        zcash_light_client_id: env::var("ZCASH_LIGHT_CLIENT_ID").ok(),

        eth_rpc: env::var("ETH_RPC").ok(),
        eth_chain_id: env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        eth_private_key: env::var("ETH_PRIVATE_KEY").ok(),
        eth_bridge_token_factory_address: env::var("ETH_BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),

        base_rpc: env::var("BASE_RPC").ok(),
        base_chain_id: env::var("BASE_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        base_private_key: env::var("BASE_PRIVATE_KEY").ok(),
        base_bridge_token_factory_address: env::var("BASE_BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),
        base_wormhole_address: env::var("BASE_WORMHOLE_ADDRESS").ok(),

        arb_rpc: env::var("ARB_RPC").ok(),
        arb_chain_id: env::var("ARB_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        arb_private_key: env::var("ARB_PRIVATE_KEY").ok(),
        arb_bridge_token_factory_address: env::var("ARB_BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),
        arb_wormhole_address: env::var("ARB_WORMHOLE_ADDRESS").ok(),

        bnb_rpc: env::var("BNB_RPC").ok(),
        bnb_chain_id: env::var("BNB_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        bnb_private_key: env::var("BNB_PRIVATE_KEY").ok(),
        bnb_bridge_token_factory_address: env::var("BNB_BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),
        bnb_wormhole_address: env::var("BNB_WORMHOLE_ADDRESS").ok(),

        solana_rpc: env::var("SOLANA_RPC").ok(),
        solana_bridge_address: env::var("SOLANA_BRIDGE_ADDRESS").ok(),
        solana_wormhole_address: env::var("SOLANA_WORMHOLE_ADDRESS").ok(),
        solana_wormhole_post_message_shim_program_id: env::var(
            "SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID",
        )
        .ok(),
        solana_wormhole_post_message_shim_event_authority: env::var(
            "SOLANA_WORMHOLE_POST_MESSAGE_SHIM_EVENT_AUTHORITY",
        )
        .ok(),
        solana_keypair: env::var("SOLANA_KEYPAIR").ok(),

        wormhole_api: env::var("WORMHOLE_API").ok(),

        btc_endpoint: env::var("BTC_ENDPOINT").ok(),
        btc_api_key: env::var("BTC_API_KEY").ok(),
        btc_basic_auth: env::var("BTC_BASIC_AUTH").ok(),
        btc_connector: env::var("BTC_CONNECTOR").ok(),
        btc: env::var("BTC").ok(),
        satoshi_relayer: env::var("SATOSHI_RELAYER").ok(),

        zcash_endpoint: env::var("ZCASH_ENDPOINT").ok(),
        zcash_api_key: env::var("ZCASH_API_KEY").ok(),
        zcash_basic_auth: env::var("ZCASH_BASIC_AUTH").ok(),
        zcash_connector: env::var("ZCASH_CONNECTOR").ok(),
        zcash: env::var("ZCASH").ok(),

        config: None,
    }
}

#[allow(clippy::too_many_lines)]
fn default_config(network: Network) -> CliConfig {
    match network {
        Network::Mainnet => CliConfig {
            near_rpc: Some(defaults::NEAR_RPC_MAINNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            near_token_locker_id: Some(defaults::NEAR_TOKEN_LOCKER_ID_MAINNET.to_owned()),
            eth_light_client_id: Some(defaults::ETH_LIGHT_CLIENT_ID_MAINNET.to_owned()),
            btc_light_client_id: Some(defaults::BTC_LIGHT_CLIENT_ID_MAINNET.to_owned()),
            zcash_light_client_id: Some(defaults::ZCASH_LIGHT_CLIENT_ID_MAINNET.to_owned()),

            eth_rpc: Some(defaults::ETH_RPC_MAINNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_MAINNET),
            eth_private_key: None,
            eth_bridge_token_factory_address: Some(
                defaults::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),

            base_rpc: Some(defaults::BASE_RPC_MAINNET.to_owned()),
            base_chain_id: Some(defaults::BASE_CHAIN_ID_MAINNET),
            base_private_key: None,
            base_bridge_token_factory_address: Some(
                defaults::BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),
            base_wormhole_address: Some(defaults::BASE_WORMHOLE_ADDRESS_MAINNET.to_owned()),

            arb_rpc: Some(defaults::ARB_RPC_MAINNET.to_owned()),
            arb_chain_id: Some(defaults::ARB_CHAIN_ID_MAINNET),
            arb_private_key: None,
            arb_bridge_token_factory_address: Some(
                defaults::ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),
            arb_wormhole_address: Some(defaults::ARB_WORMHOLE_ADDRESS_MAINNET.to_owned()),

            bnb_rpc: Some(defaults::BNB_RPC_MAINNET.to_owned()),
            bnb_chain_id: Some(defaults::BNB_CHAIN_ID_MAINNET),
            bnb_private_key: None,
            bnb_bridge_token_factory_address: Some(
                defaults::BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),
            bnb_wormhole_address: Some(defaults::BNB_WORMHOLE_ADDRESS_MAINNET.to_owned()),

            solana_rpc: Some(defaults::SOLANA_RPC_MAINNET.to_owned()),
            solana_bridge_address: Some(defaults::SOLANA_BRIDGE_ADDRESS_MAINNET.to_owned()),
            solana_wormhole_address: Some(defaults::SOLANA_WORMHOLE_ADDRESS_MAINNET.to_owned()),
            solana_wormhole_post_message_shim_program_id: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID_MAINNET.to_owned(),
            ),
            solana_wormhole_post_message_shim_event_authority: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_EVENT_AUTHORITY_MAINNET.to_owned(),
            ),
            solana_keypair: None,

            wormhole_api: Some(defaults::WORMHOLE_API_MAINNET.to_owned()),
            btc_endpoint: Some(defaults::BTC_ENDPOINT_MAINNET.to_owned()),
            btc_api_key: None,
            btc_basic_auth: None,
            btc_connector: Some(defaults::BTC_CONNECTOR_MAINNET.to_owned()),
            btc: Some(defaults::BTC_MAINNET.to_owned()),
            satoshi_relayer: Some(defaults::SATOSHI_RELAYER_MAINNET.to_owned()),

            zcash_endpoint: Some(defaults::ZCASH_ENDPOINT_MAINNET.to_owned()),
            zcash_api_key: None,
            zcash_basic_auth: None,
            zcash_connector: Some(defaults::ZCASH_CONNECTOR_MAINNET.to_owned()),
            zcash: Some(defaults::ZCASH_MAINNET.to_owned()),

            config: None,
        },
        Network::Testnet => CliConfig {
            near_rpc: Some(defaults::NEAR_RPC_TESTNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            near_token_locker_id: Some(defaults::NEAR_TOKEN_LOCKER_ID_TESTNET.to_owned()),
            eth_light_client_id: Some(defaults::ETH_LIGHT_CLIENT_ID_TESTNET.to_owned()),
            btc_light_client_id: Some(defaults::BTC_LIGHT_CLIENT_ID_TESTNET.to_owned()),
            zcash_light_client_id: Some(defaults::ZCASH_LIGHT_CLIENT_ID_TESTNET.to_owned()),

            eth_rpc: Some(defaults::ETH_RPC_TESTNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_TESTNET),
            eth_private_key: None,
            eth_bridge_token_factory_address: Some(
                defaults::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),

            base_rpc: Some(defaults::BASE_RPC_TESTNET.to_owned()),
            base_chain_id: Some(defaults::BASE_CHAIN_ID_TESTNET),
            base_private_key: None,
            base_bridge_token_factory_address: Some(
                defaults::BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),
            base_wormhole_address: Some(defaults::BASE_WORMHOLE_ADDRESS_TESTNET.to_owned()),

            arb_rpc: Some(defaults::ARB_RPC_TESTNET.to_owned()),
            arb_chain_id: Some(defaults::ARB_CHAIN_ID_TESTNET),
            arb_private_key: None,
            arb_bridge_token_factory_address: Some(
                defaults::ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),
            arb_wormhole_address: Some(defaults::ARB_WORMHOLE_ADDRESS_TESTNET.to_owned()),

            bnb_rpc: Some(defaults::BNB_RPC_TESTNET.to_owned()),
            bnb_chain_id: Some(defaults::BNB_CHAIN_ID_TESTNET),
            bnb_private_key: None,
            bnb_bridge_token_factory_address: Some(
                defaults::BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),
            bnb_wormhole_address: Some(defaults::BNB_WORMHOLE_ADDRESS_TESTNET.to_owned()),

            solana_rpc: Some(defaults::SOLANA_RPC_TESTNET.to_owned()),
            solana_bridge_address: Some(defaults::SOLANA_BRIDGE_ADDRESS_TESTNET.to_owned()),
            solana_wormhole_address: Some(defaults::SOLANA_WORMHOLE_ADDRESS_TESTNET.to_owned()),
            solana_wormhole_post_message_shim_program_id: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID_TESTNET.to_owned(),
            ),
            solana_wormhole_post_message_shim_event_authority: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_EVENT_AUTHORITY_TESTNET.to_owned(),
            ),
            solana_keypair: None,

            wormhole_api: Some(defaults::WORMHOLE_API_TESTNET.to_owned()),
            btc_endpoint: Some(defaults::BTC_ENDPOINT_TESTNET.to_owned()),
            btc_api_key: None,
            btc_basic_auth: None,
            btc_connector: Some(defaults::BTC_CONNECTOR_TESTNET.to_owned()),
            btc: Some(defaults::BTC_TESTNET.to_owned()),
            satoshi_relayer: Some(defaults::SATOSHI_RELAYER_TESTNET.to_owned()),

            zcash_endpoint: Some(defaults::ZCASH_ENDPOINT_TESTNET.to_owned()),
            zcash_api_key: None,
            zcash_basic_auth: None,
            zcash_connector: Some(defaults::ZCASH_CONNECTOR_TESTNET.to_owned()),
            zcash: Some(defaults::ZCASH_TESTNET.to_owned()),

            config: None,
        },
        Network::Devnet => CliConfig {
            near_rpc: Some(defaults::NEAR_RPC_DEVNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            near_token_locker_id: Some(defaults::NEAR_TOKEN_LOCKER_ID_DEVNET.to_owned()),
            eth_light_client_id: Some(defaults::ETH_LIGHT_CLIENT_ID_DEVNET.to_owned()),
            btc_light_client_id: Some(defaults::BTC_LIGHT_CLIENT_ID_DEVNET.to_owned()),
            zcash_light_client_id: Some(defaults::ZCASH_LIGHT_CLIENT_ID_DEVNET.to_owned()),

            eth_rpc: Some(defaults::ETH_RPC_DEVNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_DEVNET),
            eth_private_key: None,
            eth_bridge_token_factory_address: Some(
                defaults::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET.to_owned(),
            ),

            base_rpc: Some(defaults::BASE_RPC_DEVNET.to_owned()),
            base_chain_id: Some(defaults::BASE_CHAIN_ID_DEVNET),
            base_private_key: None,
            base_bridge_token_factory_address: Some(
                defaults::BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET.to_owned(),
            ),
            base_wormhole_address: Some(defaults::BASE_WORMHOLE_ADDRESS_DEVNET.to_owned()),

            arb_rpc: Some(defaults::ARB_RPC_DEVNET.to_owned()),
            arb_chain_id: Some(defaults::ARB_CHAIN_ID_DEVNET),
            arb_private_key: None,
            arb_bridge_token_factory_address: Some(
                defaults::ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET.to_owned(),
            ),
            arb_wormhole_address: Some(defaults::ARB_WORMHOLE_ADDRESS_DEVNET.to_owned()),

            bnb_rpc: Some(defaults::BNB_RPC_DEVNET.to_owned()),
            bnb_chain_id: Some(defaults::BNB_CHAIN_ID_DEVNET),
            bnb_private_key: None,
            bnb_bridge_token_factory_address: Some(
                defaults::BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET.to_owned(),
            ),
            bnb_wormhole_address: Some(defaults::BNB_WORMHOLE_ADDRESS_DEVNET.to_owned()),

            solana_rpc: Some(defaults::SOLANA_RPC_DEVNET.to_owned()),
            solana_bridge_address: Some(defaults::SOLANA_BRIDGE_ADDRESS_DEVNET.to_owned()),
            solana_wormhole_address: Some(defaults::SOLANA_WORMHOLE_ADDRESS_DEVNET.to_owned()),
            solana_wormhole_post_message_shim_program_id: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID_DEVNET.to_owned(),
            ),
            solana_wormhole_post_message_shim_event_authority: Some(
                defaults::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_EVENT_AUTHORITY_DEVNET.to_owned(),
            ),
            solana_keypair: None,

            wormhole_api: Some(defaults::WORMHOLE_API_DEVNET.to_owned()),
            btc_endpoint: Some(defaults::BTC_ENDPOINT_DEVNET.to_owned()),
            btc_api_key: None,
            btc_basic_auth: None,
            btc_connector: Some(defaults::BTC_CONNECTOR_DEVNET.to_owned()),
            btc: Some(defaults::BTC_DEVNET.to_owned()),
            satoshi_relayer: Some(defaults::SATOSHI_RELAYER_DEVNET.to_owned()),

            zcash_endpoint: Some(defaults::ZCASH_ENDPOINT_DEVNET.to_owned()),
            zcash_api_key: None,
            zcash_basic_auth: None,
            zcash_connector: Some(defaults::ZCASH_CONNECTOR_DEVNET.to_owned()),
            zcash: Some(defaults::ZCASH_DEVNET.to_owned()),

            config: None,
        },
    }
}

fn file_config(path: &str) -> CliConfig {
    let file = File::open(path).expect("Unable to open config file");
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).expect("Unable to parse config file")
}

fn combined_config(cli_config: CliConfig, network: Network) -> CliConfig {
    let file_config = cli_config
        .config
        .as_ref()
        .map_or_else(CliConfig::default, |path| file_config(path));

    cli_config
        .or(env_config())
        .or(file_config)
        .or(default_config(network))
}

#[derive(ValueEnum, Copy, Clone, Debug)]
enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    network: Network,
    #[command(subcommand)]
    cmd: OmniConnectorSubCommand,
    #[arg(value_enum, default_value_t = Mode::Regular)]
    mode: Mode,
}

#[derive(ValueEnum, Parser, Clone, Debug, PartialEq, Eq)]
enum Mode {
    Internal,
    Regular,
}

#[tokio::main]
async fn main() {
    init_logger();
    dotenv::dotenv().ok();

    let args = Arguments::parse();
    omni_connector_command::match_subcommand(args.cmd, args.network, args.mode).await;
}

fn init_logger() {
    let field_formatter = format::debug_fn(|writer, field, value| match field.name() {
        "message" => write!(writer, "{value:?}"),
        _ => write!(writer, "{field}={value:?}"),
    })
    .display_messages()
    .delimited("\n");

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let env_filter = env_filter
        .add_directive("nep141_connector=debug".parse().unwrap())
        .add_directive("eth_connector=debug".parse().unwrap())
        .add_directive("fast_bridge=debug".parse().unwrap());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_file(false)
        .with_target(false)
        .with_line_number(false)
        .with_level(false)
        .fmt_fields(field_formatter)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}
