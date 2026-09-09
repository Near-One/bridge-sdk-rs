use std::str::FromStr;

use clap::Subcommand;
use omni_connector::OmniConnector;
use omni_types::ChainKind;

use crate::config::{CliConfig, Network};
use crate::connector;

pub mod config_cmd;
pub mod svm;
pub mod token;
pub mod transfer;
pub mod utxo;

/// Everything a command needs to run: the resolved (layered) config plus the
/// global mode flags.
pub struct Ctx {
    pub network: Network,
    pub config: CliConfig,
    pub dry_run: bool,
}

impl Ctx {
    pub fn connector(&self) -> OmniConnector {
        connector::build(self.network, &self.config, self.dry_run)
    }

    pub fn indexer_api_url(&self) -> &str {
        self.config
            .bridge_indexer_api_url
            .as_deref()
            .unwrap_or_else(|| die("bridge_indexer_api_url is not configured"))
    }
}

pub fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// A transaction reference in `<chain>:<tx-hash>` form, e.g.
/// `near:8Yx7...`, `eth:0xabc...`, `sol:5oL9...`.
#[derive(Clone, Debug)]
pub struct ChainTx {
    pub chain: ChainKind,
    pub hash: String,
}

impl FromStr for ChainTx {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (chain, hash) = s
            .split_once(':')
            .ok_or("expected <chain>:<tx-hash>, e.g. near:8Yx7... or eth:0xabc...")?;
        let chain = ChainKind::from_str(chain)
            .map_err(|_| format!("unknown chain '{chain}' in transaction reference"))?;
        if hash.is_empty() {
            return Err("transaction hash is empty".to_string());
        }
        Ok(Self {
            chain,
            hash: hash.to_string(),
        })
    }
}

/// A transfer id in `<origin-chain>:<origin-nonce>` form, e.g. `eth:12345`.
#[derive(Clone, Copy, Debug)]
pub struct TransferRef {
    pub origin_chain: ChainKind,
    pub origin_nonce: u64,
}

impl FromStr for TransferRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (chain, nonce) = s
            .split_once(':')
            .ok_or("expected <origin-chain>:<origin-nonce>, e.g. eth:12345")?;
        let origin_chain = ChainKind::from_str(chain)
            .map_err(|_| format!("unknown chain '{chain}' in transfer id"))?;
        let origin_nonce = nonce
            .parse()
            .map_err(|_| format!("invalid origin nonce '{nonce}'"))?;
        Ok(Self {
            origin_chain,
            origin_nonce,
        })
    }
}

/// A token address in `<chain>:<address>` form. Keeps the raw address so
/// chain-specific clients get it in their native format.
#[derive(Clone, Debug)]
pub struct ChainToken {
    pub chain: ChainKind,
    pub address: String,
}

impl FromStr for ChainToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (chain, address) = s
            .split_once(':')
            .ok_or("expected <chain>:<token-address>, e.g. near:usdt.tether-token.near")?;
        let chain = ChainKind::from_str(chain)
            .map_err(|_| format!("unknown chain '{chain}' in token address"))?;
        if address.is_empty() {
            return Err("token address is empty".to_string());
        }
        Ok(Self {
            chain,
            address: address.to_string(),
        })
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Cross-chain transfers: start, sign, finalize, inspect
    #[command(subcommand)]
    Transfer(transfer::TransferCmd),

    /// Token deployment and management
    #[command(subcommand)]
    Token(token::TokenCmd),

    /// Bitcoin/Zcash connector operations
    #[command(subcommand)]
    Utxo(utxo::UtxoCmd),

    /// Solana/Fogo bridge program administration
    #[command(subcommand)]
    Svm(svm::SvmCmd),

    /// Inspect resolved configuration and available overrides
    #[command(subcommand)]
    Config(config_cmd::ConfigCmd),
}

pub async fn run(cmd: Command, ctx: Ctx) {
    match cmd {
        Command::Transfer(cmd) => transfer::run(cmd, &ctx).await,
        Command::Token(cmd) => token::run(cmd, &ctx).await,
        Command::Utxo(cmd) => utxo::run(cmd, &ctx).await,
        Command::Svm(cmd) => svm::run(cmd, &ctx).await,
        Command::Config(cmd) => config_cmd::run(&cmd, &ctx),
    }
}
