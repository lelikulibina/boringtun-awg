#[cfg(target_os = "linux")]
use vpn_relay::{Config, Runtime};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("vpn-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vpn-relay is supported only on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from("/etc/vpn-relay/config.toml");
    let mut check_only = false;
    let mut import_args: Option<(PathBuf, String)> = None;
    let mut yes = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_path = args.next().ok_or("--config requires a path")?.into()
            }
            "--check" => check_only = true,
            "--yes" | "-y" => yes = true,
            "--import" => {
                let source = args.next().ok_or("--import requires a source .conf path")?;
                let name = args.next().ok_or("--import requires an interface name")?;
                import_args = Some((source.into(), name));
            }
            "-h" | "--help" => {
                println!("Usage:\n  vpn-relay [--config PATH] [--check]\n  vpn-relay [--config PATH] --import WG.conf INTERFACE [--yes]\n\nOptions:\n  -c, --config PATH  Configuration file (default: /etc/vpn-relay/config.toml)\n      --check        Validate configuration and exit\n      --import       Import WireGuard/AmneziaWG configuration\n  -y, --yes          Replace an existing interface without prompting");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    if let Some((source, name)) = import_args {
        let exists = vpn_relay::import::interface_exists(&config_path, &name)?;
        if exists && !yes {
            eprintln!("Интерфейс '{name}' уже существует. Заменить его? [y/N]");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "y" | "yes" | "д" | "да"
            ) {
                println!("Импорт отменён; конфигурация не изменена.");
                return Ok(());
            }
        }
        let report = vpn_relay::import::import_file(&source, &config_path, &name, exists)?;
        println!(
            "Импортирован интерфейс '{name}': {:?}, роль {:?}.",
            report.protocol, report.role
        );
        if report.replaced {
            println!(
                "Существующий интерфейс заменён; остальные интерфейсы и routing rules сохранены."
            );
        }
        if report.warnings.is_empty() {
            println!("Все распознанные параметры перенесены.");
        } else {
            println!("Параметры, которые не применяются и не были импортированы:");
            for warning in report.warnings {
                println!("  - {warning}");
            }
        }
        println!("Конфигурация сохранена: {}", config_path.display());
        return Ok(());
    }

    let config = Config::load(&config_path)?;
    if check_only {
        println!("configuration is valid: {}", config_path.display());
        return Ok(());
    }

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.daemon.log_level.clone()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    tracing::info!(path = %config_path.display(), "starting vpn-relay");
    let runtime = Runtime::start(config)?;
    runtime.run()?;
    Ok(())
}
