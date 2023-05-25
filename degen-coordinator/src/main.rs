use std::str::FromStr;
use bitcoin::secp256k1::SecretKey;


fn main() {
    let ALICE: SecretKey = SecretKey::from_str("1d799760009ca66cb0ad05a80e5b781deabf0550923fad7ad4417f61702f6353")
        .unwrap();
    let BOB: SecretKey = SecretKey::from_str("91436bd90d9cde7ba3162375b7692ae3f22ad01586cb4520bffae48d3a480f6a")
        .unwrap();

    let miner_coordinator = MinerCoordinator::new();
    let alice_miner_signer = MinerSigner::new();
    let bob_miner_signer = MinerSigner::new();
}

struct MinerCoordinator {}

impl MinerCoordinator {
    fn new() -> Self {
        Self {}
    }

    fn run_static_key_generation(&self) {
    }
}


struct MinerSigner {}

impl MinerSigner {
    fn new() -> Self {
        Self {}
    }
}
