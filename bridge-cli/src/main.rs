use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{field::MakeExt, fmt::format, EnvFilter, FmtSubscriber};

mod api;
mod commands;
mod config;
mod connector;
mod defaults;

use commands::{Command, Ctx};
use config::{CliConfig, Network};

#[derive(Parser, Debug)]
#[command(
    name = "bridge-cli",
    version,
    about = "Omni Bridge operations CLI",
    after_help = "Connection, key, and contract overrides are configured via env vars, a JSON \
                  config file (--config), or hidden flags — run `bridge-cli config vars` to list \
                  them and `bridge-cli config show` to see the resolved values."
)]
struct Arguments {
    /// Network to operate on (mainnet must be selected explicitly)
    #[arg(
        short,
        long,
        global = true,
        env = "BRIDGE_NETWORK",
        value_enum,
        default_value = "testnet"
    )]
    network: Network,

    /// Path to a JSON config file with connection/contract overrides
    #[arg(long, global = true, env = "BRIDGE_CONFIG", value_name = "PATH")]
    config: Option<String>,

    /// Build and print the unsigned transaction instead of signing and
    /// broadcasting it (supported for NEAR and SVM targets)
    #[arg(long, global = true, env = "DRY_RUN")]
    dry_run: bool,

    #[command(flatten)]
    overrides: CliConfig,

    #[command(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() {
    init_logger();
    dotenv::dotenv().ok();

    let args = Arguments::parse();

    // `config vars` is static documentation — usable before any network is set.
    if let Command::Config(commands::config_cmd::ConfigCmd::Vars) = &args.cmd {
        commands::config_cmd::print_vars();
        return;
    }

    let config = config::resolve(args.overrides, args.config.as_deref(), args.network);
    let ctx = Ctx {
        network: args.network,
        config,
        dry_run: args.dry_run,
    };

    commands::run(args.cmd, ctx).await;
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
