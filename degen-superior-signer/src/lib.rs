/// Module for defining the CLI and its operations
pub mod cli;
/// Module for secp256k1 operations
pub mod secp256k1;
/// Module for signer operations
pub mod signer;

// set via _compile-time_ envars
const GIT_BRANCH: Option<&'static str> = option_env!("GIT_BRANCH");
const GIT_COMMIT: Option<&'static str> = option_env!("GIT_COMMIT");

#[cfg(debug_assertions)]
const BUILD_TYPE: &str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_TYPE: &'static str = "release";

pub fn version() -> String {
    format!(
        "degen-superior-signer {} {} {}",
        BUILD_TYPE,
        GIT_BRANCH.unwrap_or(""),
        GIT_COMMIT.unwrap_or("")
    )
}