use clap::{Args, Parser, Subcommand, ValueEnum};
use eth_connector_command::EthConnectorSubCommand;
use fast_bridge_command::FastBridgeSubCommand;
use nep141_connector_command::Nep141ConnectorSubCommand;
use serde::Deserialize;
use std::{env, fs::File, io::BufReader};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{field::MakeExt, fmt::format, EnvFilter, FmtSubscriber};

mod defaults;
mod eth_connector_command;
mod fast_bridge_command;
mod nep141_connector_command;

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
    near_light_client_eth_address: Option<String>,

    #[arg(long)]
    eth_rpc: Option<String>,
    #[arg(long)]
    eth_chain_id: Option<u64>,
    #[arg(long)]
    eth_private_key: Option<String>,
    #[arg(long)]
    eth_bridge_token_factory_address: Option<String>,
    #[arg(long)]
    eth_custodian_address: Option<String>,
    #[arg(long)]
    eth_connector_account_id: Option<String>,

    #[arg(long)]
    fast_bridge_account_id: Option<String>,
    #[arg(long)]
    fast_bridge_address: Option<String>,

    #[arg(long)]
    config_file: Option<String>,
}

impl CliConfig {
    fn or(self, other: Self) -> Self {
        Self {
            near_rpc: self.near_rpc.or(other.near_rpc),
            near_signer: self.near_signer.or(other.near_signer),
            near_private_key: self.near_private_key.or(other.near_private_key),
            near_token_locker_id: self.near_token_locker_id.or(other.near_token_locker_id),
            near_light_client_eth_address: self
                .near_light_client_eth_address
                .or(other.near_light_client_eth_address),

            eth_rpc: self.eth_rpc.or(other.eth_rpc),
            eth_chain_id: self.eth_chain_id.or(other.eth_chain_id),
            eth_private_key: self.eth_private_key.or(other.eth_private_key),
            eth_bridge_token_factory_address: self
                .eth_bridge_token_factory_address
                .or(other.eth_bridge_token_factory_address),
            eth_custodian_address: self.eth_custodian_address.or(other.eth_custodian_address),
            eth_connector_account_id: self
                .eth_connector_account_id
                .or(other.eth_connector_account_id),

            fast_bridge_account_id: self.fast_bridge_account_id.or(other.fast_bridge_account_id),
            fast_bridge_address: self.fast_bridge_address.or(other.fast_bridge_address),

            config_file: self.config_file.or(other.config_file),
        }
    }
}

fn env_config() -> CliConfig {
    CliConfig {
        near_rpc: env::var("NEAR_RPC").ok(),
        near_signer: env::var("NEAR_SIGNER").ok(),
        near_private_key: env::var("NEAR_PRIVATE_KEY").ok(),
        near_token_locker_id: env::var("TOKEN_LOCKER_ID").ok(),
        near_light_client_eth_address: env::var("NEAR_LIGHT_CLIENT_ADDRESS").ok(),

        eth_rpc: env::var("ETH_RPC").ok(),
        eth_chain_id: env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        eth_private_key: env::var("ETH_PRIVATE_KEY").ok(),
        eth_bridge_token_factory_address: env::var("ETH_BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),
        eth_custodian_address: env::var("ETH_CUSTODIAN_ADDRESS").ok(),
        eth_connector_account_id: env::var("ETH_CONNECTOR_ACCOUNT_ID").ok(),

        fast_bridge_account_id: env::var("FAST_BRIDGE_ACCOUNT_ID").ok(),
        fast_bridge_address: env::var("FAST_BRIDGE_ADDRESS").ok(),

        config_file: None,
    }
}

fn default_config(network: Network) -> CliConfig {
    match network {
        Network::Mainnet => CliConfig {
            near_rpc: Some(defaults::NEAR_RPC_MAINNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            near_token_locker_id: Some(defaults::NEAR_TOKEN_LOCKER_ID_MAINNET.to_owned()),
            near_light_client_eth_address: Some(
                defaults::NEAR_LIGHT_CLIENT_ETH_ADDRESS_MAINNET.to_owned(),
            ),

            eth_rpc: Some(defaults::ETH_RPC_MAINNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_MAINNET),
            eth_private_key: None,
            eth_bridge_token_factory_address: Some(
                defaults::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),
            eth_connector_account_id: Some(defaults::ETH_CONNECTOR_ACCOUNT_ID_MAINNET.to_owned()),
            eth_custodian_address: Some(defaults::ETH_CUSTODIAN_ADDRESS_MAINNET.to_owned()),

            fast_bridge_account_id: Some(defaults::FAST_BRIDGE_ACCOUNT_ID_MAINNET.to_owned()),
            fast_bridge_address: Some(defaults::FAST_BRIDGE_ADDRESS_MAINNET.to_owned()),

            config_file: None,
        },
        Network::Testnet => CliConfig {
            near_rpc: Some(defaults::NEAR_RPC_TESTNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            near_token_locker_id: Some(defaults::NEAR_TOKEN_LOCKER_ID_TESTNET.to_owned()),
            near_light_client_eth_address: Some(
                defaults::NEAR_LIGHT_CLIENT_ETH_ADDRESS_TESTNET.to_owned(),
            ),

            eth_rpc: Some(defaults::ETH_RPC_TESTNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_TESTNET),
            eth_private_key: None,
            eth_bridge_token_factory_address: Some(
                defaults::ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),
            eth_connector_account_id: Some(defaults::ETH_CONNECTOR_ACCOUNT_ID_TESTNET.to_owned()),
            eth_custodian_address: Some(defaults::ETH_CUSTODIAN_ADDRESS_TESTNET.to_owned()),

            fast_bridge_account_id: Some(defaults::FAST_BRIDGE_ACCOUNT_ID_TESTNET.to_owned()),
            fast_bridge_address: Some(defaults::FAST_BRIDGE_ADDRESS_TESTNET.to_owned()),

            config_file: None,
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
        .config_file
        .as_ref()
        .map_or_else(CliConfig::default, |path| file_config(path));

    cli_config
        .or(env_config())
        .or(file_config)
        .or(default_config(network))
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Nep141Connector {
        #[clap(subcommand)]
        cmd: Nep141ConnectorSubCommand,
    },
    EthConnector {
        #[clap(subcommand)]
        cmd: EthConnectorSubCommand,
    },
    FastBridge {
        #[clap(subcommand)]
        cmd: FastBridgeSubCommand,
    },
}

#[derive(ValueEnum, Copy, Clone, Debug)]
enum Network {
    Mainnet,
    Testnet,
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    network: Network,
    #[command(subcommand)]
    cmd: SubCommand,
}

#[tokio::main]
async fn main() {
    init_logger();
    dotenv::dotenv().ok();
    let args = Arguments::parse();

    match args.cmd {
        SubCommand::Nep141Connector { cmd } => {
            nep141_connector_command::match_subcommand(cmd, args.network).await;
        }
        SubCommand::EthConnector { cmd } => {
            eth_connector_command::match_subcommand(cmd, args.network).await;
        }
        SubCommand::FastBridge { cmd } => {
            fast_bridge_command::match_subcommand(cmd, args.network).await;
        }
    }
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
