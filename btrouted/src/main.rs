use btrouted::{Config, Runtime};
use std::path::PathBuf;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(error) = run() {
        eprintln!("btrouted: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from("/etc/btrouted/config.toml");
    let mut check_only = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_path = args.next().ok_or("--config requires a path")?.into();
            }
            "--check" => check_only = true,
            "-h" | "--help" => {
                println!("Usage: btrouted [--config PATH] [--check]\n\n  -c, --config PATH  Configuration file (default: /etc/btrouted/config.toml)\n      --check        Validate configuration and exit");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let config = Config::load(&config_path)?;
    if check_only {
        println!("configuration is valid: {}", config_path.display());
        return Ok(());
    }

    tracing::info!(path = %config_path.display(), "starting btrouted");
    let runtime = Runtime::start(config)?;
    runtime.run();
}
