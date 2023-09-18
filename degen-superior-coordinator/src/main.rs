use clap::Parser;
use degen_base_signer::logging;
use degen_superior_coordinator::cli::{Cli, Command};
use degen_superior_coordinator::config::Config;
use degen_superior_coordinator::coordinator::{Coordinator, StacksCoordinator};
use tracing::{error, info, warn};

fn main() {
    let cli = Cli::parse();

    logging::initiate_tracing_subscriber();

    //TODO: get configs from sBTC contract
    match Config::from_path(&cli.config) {
        Ok(mut config) => {
            config.signer_config_path = Some(cli.signer_config);
            if cli.start_block_height == Some(0) {
                error!("Invalid start block height. Must specify a value greater than 0.",);
                return;
            }
            config.start_block_height = cli.start_block_height;
            match StacksCoordinator::try_from(&config) {
                Ok(mut coordinator) => {
                    // Determine what action the caller wishes to perform
                    match cli.command {
                        Command::Run => {
                            info!("Running Coordinator");
                            //TODO: set up coordination with the stacks node
                            if let Err(e) = coordinator.run(config.polling_interval) {
                                error!("An error occurred running the coordinator: {}", e);
                            }
                        }
                        Command::Dkg => {
                            info!("Running DKG Round");
                            if let Err(e) = coordinator.run_dkg_round() {
                                error!("An error occurred during DKG round: {}", e);
                            }
                        }
                        Command::DkgSign => {
                            info!("Running DKG Round");
                            if let Err(e) = coordinator.run_dkg_round() {
                                warn!("An error occurred during DKG round: {}", e);
                            };
                            // TODO: degens - move separately
                            coordinator.run_create_script();
                            info!("Running Signing Round");
                            let (signature, schnorr_proof) =
                                match coordinator.sign_message("Hello, world!") {
                                    Ok((sig, proof)) => (sig, proof),
                                    Err(e) => {
                                        panic!("signing message failed: {e}");
                                    }
                                };
                            info!(
                                "Got good signature ({},{}) and schnorr proof ({},{})",
                                &signature.R, &signature.z, &schnorr_proof.r, &schnorr_proof.s
                            );
                        }
                    };
                }
                Err(e) => {
                    error!("An error occurred creating coordinator: {}", e);
                }
            }
        }
        Err(e) => {
            error!(
                "An error occurred reading config file {}: {}",
                cli.config, e
            );
        }
    }
}