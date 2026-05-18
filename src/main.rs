mod cli;

use clap::Parser;
use cli::Commands;
use nonce_cracker::{logging::init as init_logging, AppContext, Config};
use tracing::{error, info};

fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    };

    let console = std::env::var("NONCE_CRACKER_LOG_CONSOLE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(true);

    if let Err(e) = init_logging(&config.log_dir, console) {
        eprintln!("logging: {e}");
        std::process::exit(1);
    }

    let ctx = AppContext::new(config);

    {
        let shutdown = ctx.shutdown.clone();
        ctrlc::set_handler(move || {
            info!("shutdown signal received");
            shutdown.signal();
        })
        .unwrap_or_else(|e| {
            eprintln!("failed to register signal handler: {e}");
            std::process::exit(1);
        });
    }

    info!(version = ctx.config.version, "starting");

    let cli = cli::Cli::parse();
    let code = match cli.command.unwrap_or(Commands::Example) {
        Commands::Example => cli::run_example(&ctx).map_or_else(
            |e| {
                error!("example failed: {e}");
                1
            },
            |()| 0,
        ),
        Commands::Search(args) => cli::run_search(&ctx, &args).map_or_else(
            |e| {
                error!("search failed: {e}");
                1
            },
            |()| 0,
        ),
    };

    info!("shutting down");
    std::process::exit(code);
}
