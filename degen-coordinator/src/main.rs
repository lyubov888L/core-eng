use std::collections::BTreeMap;
use std::error::Error;
use std::str::FromStr;

use bitcoin::secp256k1::SecretKey;

use frost_signer::{
    net::{Message},
    signing_round::{
        DkgBegin,
        DkgPublicShare,
        MessageTypes
    },
};
use tracing::{debug, info, warn};
use wsts::Scalar;
use frost_signer::signing_round::Signable;

fn main() {
    let ALICE: SecretKey = SecretKey::from_str("1d799760009ca66cb0ad05a80e5b781deabf0550923fad7ad4417f61702f6353")
        .unwrap();
    let BOB: SecretKey = SecretKey::from_str("91436bd90d9cde7ba3162375b7692ae3f22ad01586cb4520bffae48d3a480f6a")
        .unwrap();

    let miner_coordinator = MinerCoordinator::new();
    let alice_miner_signer = MinerSigner::new(String::from("Alice"));
    let bob_miner_signer = MinerSigner::new(String::from("Bob"));
}

struct MinerCoordinator {
    current_dkg_id: u64,
    current_dkg_public_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShare>,
    network_private_key: Scalar,
}

impl MinerCoordinator {
    fn new() -> Self {
        Self {
            current_dkg_id: 0,
            current_dkg_public_id: 0,
            dkg_public_shares: Default::default(),
            // TODO
            network_private_key: Scalar::from()
        }
    }

    fn run_static_key_generation(&mut self) {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round #{}", self.current_dkg_id);
        self.start_public_shares();

        // let public_key = self.wait_for_public_shares()?;

        // self.start_private_shares()?;
        // self.wait_for_dkg_end()?;

        // Ok(public_key)
    }

    fn start_public_shares(&mut self) -> Result<(), ()> {
        self.dkg_public_shares.clear();

        info!(
            "DKG Round #{}: Starting Public Share Distribution Round #{}",
            self.current_dkg_id, self.current_dkg_public_id
        );

        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_message = Message {
            sig: dkg_begin.sign(&self.network_private_key).expect(""),
            msg: MessageTypes::DkgBegin(dkg_begin),
        };
        // self.network.send_message(dkg_begin_message)?;

        Ok(())
    }
}


struct MinerSigner {
    name: String,
}

impl MinerSigner {
    fn new(name: String) -> Self {
        Self {
            name
        }
    }

    pub fn receive_message(&self) {
        info!("{} received message", self.name)
    }
}
