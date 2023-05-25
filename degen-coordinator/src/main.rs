use std::str::FromStr;
use bitcoin::secp256k1::SecretKey;


fn main() {
    let ALICE: SecretKey = SecretKey::from_str("1d799760009ca66cb0ad05a80e5b781deabf0550923fad7ad4417f61702f6353")
        .unwrap();
    let BOB: SecretKey = SecretKey::from_str("91436bd90d9cde7ba3162375b7692ae3f22ad01586cb4520bffae48d3a480f6a")
        .unwrap();


}

