use blockstack_lib::{
    chainstate::stacks::address::StacksAddressExtensions, chainstate::stacks::StacksTransaction,
    codec::StacksMessageCodec, types::chainstate::StacksAddress,
};
use reqwest::blocking::Client;
use serde_json::{from_value, Value};

use crate::stacks_node::{PegInOp, PegOutRequestOp, StacksNode};

pub struct NodeClient {
    node_url: String,
    client: Client,
}

impl NodeClient {
    pub fn new(url: &str) -> Self {
        Self {
            node_url: url.to_string(),
            client: Client::new(),
        }
    }

    fn build_url(&self, route: &str) -> String {
        format!("{}{}", self.node_url, route)
    }
}

impl StacksNode for NodeClient {
    fn get_peg_in_ops(&self, block_height: u64) -> Vec<PegInOp> {
        let url = self.build_url(&format!("/v2/burn_ops/peg_in/{block_height}"));

        self.client
            .get(url)
            .send()
            .and_then(|res| res.json::<Value>())
            .map(|json| from_value(json["peg_in"].clone()).unwrap())
            .unwrap()
    }

    fn get_peg_out_request_ops(&self, block_height: u64) -> Vec<PegOutRequestOp> {
        let url = self.build_url(&format!("/v2/burn_ops/peg_out_request/{block_height}"));

        self.client
            .get(url)
            .send()
            .and_then(|res| res.json::<Value>())
            .map(|json| from_value(json["peg_in"].clone()).unwrap())
            .unwrap()
    }

    fn burn_block_height(&self) -> u64 {
        let url = self.build_url("/v2/info");

        self.client
            .get(url)
            .send()
            .and_then(|res| res.json::<Value>())
            .map(|json| json["burn_block_height"].as_u64().unwrap())
            .unwrap()
    }

    fn next_nonce(&self, addr: StacksAddress) -> u64 {
        let url = self.build_url(&format!("/v2/accounts/{}", addr.to_b58()));

        self.client
            .get(url)
            .send()
            .and_then(|res| res.json::<Value>())
            .map(|json| json["nonce"].as_u64().unwrap())
            .unwrap()
            + 1
    }

    fn broadcast_transaction(&self, tx: &StacksTransaction) {
        let url = self.build_url("/v2/transactions");

        let mut buffer = vec![];
        tx.consensus_serialize(&mut buffer).unwrap();

        let _return = self
            .client
            .post(url)
            .body(buffer)
            // .json(tx)
            .send()
            .and_then(|res| res.json::<Value>())
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use blockstack_lib::{
        chainstate::stacks::{
            CoinbasePayload, SinglesigHashMode, SinglesigSpendingCondition, TransactionAnchorMode,
            TransactionAuth, TransactionPayload, TransactionPostConditionMode,
            TransactionPublicKeyEncoding, TransactionSpendingCondition, TransactionVersion,
        },
        util::{hash::Hash160, secp256k1::MessageSignature},
    };

    use super::*;

    // Temporary debugging
    #[test]
    #[ignore]
    fn send_tx() {
        let client = NodeClient::new("http://localhost:20443");

        client.broadcast_transaction(&StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0,
            auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
                SinglesigSpendingCondition {
                    hash_mode: SinglesigHashMode::P2PKH,
                    signer: Hash160([0; 20]),
                    nonce: 0,
                    tx_fee: 0,
                    key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                    signature: MessageSignature([0; 65]),
                },
            )),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None),
        });
    }
}