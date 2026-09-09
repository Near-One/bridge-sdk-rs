use clap::Subcommand;
use omni_types::ChainKind;

use crate::connector::{ensure_dry_run_allowed, extract_solana_keypair};

use super::{die, Ctx};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum SvmChainArg {
    Sol,
    Fogo,
}

impl From<SvmChainArg> for ChainKind {
    fn from(value: SvmChainArg) -> Self {
        match value {
            SvmChainArg::Sol => ChainKind::Sol,
            SvmChainArg::Fogo => ChainKind::Fogo,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum SvmCmd {
    /// Initialize the OmniBridge program
    Initialize {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
        #[clap(
            short,
            long,
            help = "Program keypair in Base58 or path to a .json keypair file"
        )]
        program_keypair: String,
    },

    /// Get the deployed program version
    Version {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
    },

    /// Set the program admin
    SetAdmin {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
        #[clap(short, long, help = "Admin pubkey")]
        admin: String,
    },

    /// Pause the program
    Pause {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
    },

    /// Update a bridged token's metadata
    UpdateMetadata {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
        #[clap(short, long, help = "Token mint to update the metadata for")]
        token: String,
        #[clap(short, long, help = "New metadata URI")]
        uri: Option<String>,
        #[clap(long, help = "New name")]
        name: Option<String>,
        #[clap(short, long, help = "New symbol")]
        symbol: Option<String>,
    },

    /// Get the token vault (locker) PDA for a mint
    #[clap(hide = true)]
    TokenVault {
        #[clap(long, value_enum, help = "SVM chain (sol or fogo)")]
        chain: SvmChainArg,
        #[clap(short, long, help = "Token mint address")]
        token: String,
    },
}

pub async fn run(cmd: SvmCmd, ctx: &Ctx) {
    match cmd {
        SvmCmd::Initialize {
            chain,
            program_keypair,
        } => {
            // `initialize` needs the program keypair as a real signer; the
            // dry-run flow can't represent that, so reject it outright.
            if ctx.dry_run {
                die(
                    "--dry-run is not supported for svm initialize (the program keypair must sign)",
                );
            }
            ctx.connector()
                .svm_initialize(chain.into(), extract_solana_keypair(&program_keypair))
                .await
                .unwrap();
        }
        SvmCmd::Version { chain } => {
            ctx.connector().svm_get_version(chain.into()).await.unwrap();
        }
        SvmCmd::SetAdmin { chain, admin } => {
            ensure_dry_run_allowed(ctx, chain.into());
            ctx.connector()
                .svm_set_admin(
                    chain.into(),
                    admin
                        .parse()
                        .unwrap_or_else(|e| die(format!("invalid admin pubkey: {e}"))),
                )
                .await
                .unwrap();
        }
        SvmCmd::Pause { chain } => {
            ensure_dry_run_allowed(ctx, chain.into());
            ctx.connector().svm_pause(chain.into()).await.unwrap();
        }
        SvmCmd::UpdateMetadata {
            chain,
            token,
            uri,
            name,
            symbol,
        } => {
            ensure_dry_run_allowed(ctx, chain.into());
            ctx.connector()
                .svm_update_metadata(
                    chain.into(),
                    token
                        .parse()
                        .unwrap_or_else(|e| die(format!("invalid token mint: {e}"))),
                    name,
                    symbol,
                    uri,
                )
                .await
                .unwrap();
        }
        SvmCmd::TokenVault { chain, token } => {
            ctx.connector()
                .svm_get_token_vault(
                    chain.into(),
                    token
                        .parse()
                        .unwrap_or_else(|e| die(format!("invalid token mint: {e}"))),
                )
                .await
                .unwrap();
        }
    }
}
