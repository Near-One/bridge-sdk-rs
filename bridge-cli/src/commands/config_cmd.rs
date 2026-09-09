use clap::Subcommand;

use crate::config::CliConfig;

use super::Ctx;

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Show the resolved configuration for the selected network (secrets
    /// redacted)
    Show,
    /// List every override flag and its environment variable. All of them are
    /// also accepted as keys in the JSON config file (--config)
    Vars,
}

pub fn run(cmd: &ConfigCmd, ctx: &Ctx) {
    match cmd {
        ConfigCmd::Show => show(&ctx.config),
        ConfigCmd::Vars => print_vars(),
    }
}

fn is_secret(flag: &str) -> bool {
    ["private-key", "keypair", "api-key", "basic-auth"]
        .iter()
        .any(|s| flag.contains(s))
}

fn show(config: &CliConfig) {
    for (flag, _, value) in config.entries() {
        let name = flag.trim_start_matches("--");
        match value {
            Some(_) if is_secret(&flag) => println!("{name} = <redacted>"),
            Some(value) => println!("{name} = {value}"),
            None => println!("{name} ="),
        }
    }
}

pub fn print_vars() {
    let entries = CliConfig::default().entries();
    let width = entries
        .iter()
        .map(|(flag, _, _)| flag.len())
        .max()
        .unwrap_or(0);
    println!("Overrides are resolved as: CLI flag > env var > config file (--config) > network default\n");
    for (flag, env, _) in entries {
        println!("{flag:<width$}  {env}");
    }
}
