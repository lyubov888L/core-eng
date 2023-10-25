use bdk::miniscript::psbt::SighashError;
use chrono::Local;
use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{PartiallySignedTransaction, Prevouts};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::{base58, taproot};
use bitcoin::{Transaction, Txid};
use bitcoin::{
    EcdsaSighashType, KeyPair, Network, OutPoint, PrivateKey, PublicKey, SchnorrSighashType,
    Script, TxOut, Witness, XOnlyPublicKey,
};
use blockstack_lib::burnchains::bitcoin::address::{BitcoinAddress, SegwitBitcoinAddress};
use blockstack_lib::burnchains::bitcoin::{
    BitcoinNetworkType, BitcoinTransaction, BitcoinTxOutput,
};
use blockstack_lib::burnchains::{
    BurnchainBlockHeader, BurnchainTransaction, PrivateKey as PrivateKeyTrait,
};
use blockstack_lib::chainstate::burn::operations::PegOutRequestOp;
use blockstack_lib::chainstate::burn::Opcodes;
use blockstack_lib::chainstate::stacks::address::PoxAddress;
use bitcoin::util::address::Address;
use blockstack_lib::chainstate::stacks::{StacksPrivateKey, StacksTransaction, TransactionVersion};
use blockstack_lib::types::chainstate::{BurnchainHeaderHash, StacksAddress};
use blockstack_lib::util::hash::{Hash160, Sha256Sum};
use blockstack_lib::vm::ContractName;
use hashbrown::{HashMap, HashSet};
use p256k1::{
    ecdsa,
    point::{Compressed, Point},
    scalar::Scalar,
};
use rand::{random, Rng};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use bdk::miniscript::ToPublicKey;
use bitcoin::psbt::serialize::Serialize as TransactionSerializer;
use bitcoin::util::taproot::{TapBranchHash, TaprootSpendInfo, TapSighashHash};
use itertools::Itertools;
use tracing::{debug, info, warn};
use url::Url;
use wsts::{
    common::{PolyCommitment, PublicNonce, SignatureShare},
    traits::Signer as SignerTrait,
    v1,
};
use std::io::Write;
use crate::bitcoin_node::{BitcoinNode, LocalhostBitcoinNode, UTXO};
use crate::bitcoin_scripting::{
    create_refund_tx, create_script_refund, create_script_unspendable, create_tree,
    create_tx_from_user_to_script, get_current_block_height,
    sign_tx_script_refund, sign_tx_user_to_script, get_good_utxo_from_list,
};
use crate::bitcoin_wallet::BitcoinWallet;
use crate::peg_wallet::{BitcoinWallet as BitcoinWalletTrait, StacksWallet as PegWallet};
use crate::stacks_node::client::NodeClient;
use crate::stacks_wallet::StacksWallet;
use crate::{
    config::PublicKeys,
    signer::Signer as FrostSigner,
    state_machine::{Error as StateMachineError, StateMachine, States},
    util::{decrypt, encrypt, make_shared_secret},
};
use crate::stacks_node::StacksNode;
use blockstack_lib::burnchains::Address as BitcoinAddressTrait;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("InvalidPartyID")]
    InvalidPartyID,
    #[error("InvalidDkgPublicShare")]
    InvalidDkgPublicShare,
    #[error("InvalidDkgPrivateShares")]
    InvalidDkgPrivateShares(Vec<u32>),
    #[error("InvalidNonceResponse")]
    InvalidNonceResponse,
    #[error("InvalidSignatureShare")]
    InvalidSignatureShare,
    #[error("State Machine Error: {0}")]
    StateMachineError(#[from] StateMachineError),
    #[error("Error occured during signing: {0}")]
    SigningError(#[from] SighashError),
    #[error("The amount you're sending is smaller than the fee")]
    FeeError,
    #[error("UTXO amount too low")]
    UTXOAmount,
}

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize)]
pub enum UtxoError {
    #[error("Invalid UTXO.")]
    InvalidUTXO,
}

pub trait Signable {
    fn hash(&self, hasher: &mut Sha256);

    fn sign(&self, private_key: &Scalar) -> Result<Vec<u8>, ecdsa::Error> {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        match ecdsa::Signature::new(hash.as_slice(), private_key) {
            Ok(sig) => Ok(sig.to_bytes().to_vec()),
            Err(e) => Err(e),
        }
    }

    fn verify(&self, signature: &[u8], public_key: &ecdsa::PublicKey) -> bool {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        let sig = match ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sig.verify(hash.as_slice(), public_key)
    }
}

pub struct SigningRound {
    pub dkg_id: u64,
    pub dkg_public_id: u64,
    pub sign_id: u64,
    pub sign_nonce_id: u64,
    pub threshold: u32,
    pub total_signers: u32,
    pub total_keys: u32,
    pub signer: Signer,
    pub state: States,
    pub commitments: BTreeMap<u32, PolyCommitment>,
    pub shares: HashMap<u32, HashMap<u32, Vec<u8>>>,
    pub public_nonces: Vec<PublicNonce>,
    pub network_private_key: Scalar,
    pub public_keys: PublicKeys,
    // TODO: should be encrypted, i guess?
    pub contract_name: ContractName,
    pub contract_address: StacksAddress,
    pub aggregate_public_key: Point,
    pub stacks_private_key: StacksPrivateKey,
    pub stacks_address: StacksAddress,
    pub stacks_node_rpc_url: Url,
    pub local_stacks_node: NodeClient,
    pub stacks_wallet: StacksWallet,
    pub stacks_version: TransactionVersion,
    pub bitcoin_private_key: SecretKey,
    pub bitcoin_xonly_public_key: XOnlyPublicKey,
    pub bitcoin_node_rpc_url: Url,
    pub local_bitcoin_node: LocalhostBitcoinNode,
    pub bitcoin_wallet: BitcoinWallet,
    pub transaction_fee: u64,
    pub bitcoin_network: Network,

    pub script_addresses: BTreeMap<PublicKey, BitcoinAddress>,
}

pub struct Signer {
    pub frost_signer: v1::Signer,
    pub signer_id: u32,
}

impl StateMachine for SigningRound {
    fn move_to(&mut self, state: States) -> Result<(), StateMachineError> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &States) -> Result<(), StateMachineError> {
        let prev_state = &self.state;
        let accepted = match state {
            States::Idle => true,
            States::DkgPublicDistribute => {
                prev_state == &States::Idle
                    || prev_state == &States::DkgPublicGather
                    || prev_state == &States::DkgPrivateDistribute
            }
            States::DkgPublicGather => prev_state == &States::DkgPublicDistribute,
            States::DkgPrivateDistribute => prev_state == &States::DkgPublicGather,
            States::DkgPrivateGather => prev_state == &States::DkgPrivateDistribute,
            States::SignGather => prev_state == &States::Idle,
            States::Signed => prev_state == &States::SignGather,
            States::DegensScriptDistribute => prev_state == &States::Idle,
            States::DegensScriptGather => prev_state == &States::DegensScriptDistribute,
            // TODO degens: add states for scripts
        };
        if accepted {
            info!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(StateMachineError::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum DkgStatus {
    Success,
    Failure(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum MessageTypes {
    DkgBegin(DkgBegin),
    DkgPrivateBegin(DkgBegin),
    DkgEnd(DkgEnd),
    DkgPublicEnd(DkgEnd),
    DkgPublicShare(DkgPublicShare),
    DkgPrivateShares(DkgPrivateShares),
    NonceRequest(NonceRequest),
    NonceResponse(NonceResponse),
    SignShareRequest(SignatureShareRequest),
    SignShareResponse(SignatureShareResponse),
    SigShareRequestPox(SigShareRequestPox),
    SigShareResponsePox(SigShareResponsePox),
    VoteOutActorRequest(VoteOutActorRequest),
    DegensCreateScriptsRequest(DegensScriptRequest),
    DegensCreateScriptsResponse(DegensScriptResponse),
    DegensSpendScripts(DegensSpendScript),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgPublicShare {
    pub dkg_id: u64,
    pub dkg_public_id: u64,
    pub party_id: u32,
    pub public_share: PolyCommitment,
}

impl Signable for DkgPublicShare {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.dkg_public_id.to_be_bytes());
        hasher.update(self.party_id.to_be_bytes());
        for a in &self.public_share.A {
            hasher.update(a.compress().as_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgPrivateShares {
    pub dkg_id: u64,
    pub key_id: u32,
    /// Encrypt the shares using AES-GCM with a key derived from ECDH
    pub private_shares: HashMap<u32, Vec<u8>>,
}

impl Signable for DkgPrivateShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.key_id.to_be_bytes());
        // make sure we iterate sequentially
        // TODO: change this once WSTS goes to 1 based indexing for key_ids, or change to BTreeMap
        for id in 0..self.private_shares.len() as u32 {
            hasher.update(id.to_be_bytes());
            hasher.update(&self.private_shares[&id]);
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgBegin {
    pub dkg_id: u64, //TODO: Strong typing for this, alternatively introduce a type alias
}

impl Signable for DkgBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgEnd {
    pub dkg_id: u64,
    pub signer_id: u32,
    pub status: DkgStatus,
}

impl Signable for DkgEnd {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_END".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NonceRequest {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub sign_nonce_id: u64,
}

impl Signable for NonceRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_nonce_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NonceResponse {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub sign_nonce_id: u64,
    pub signer_id: u32,
    pub key_ids: Vec<u32>,
    pub nonces: Vec<PublicNonce>,
}

impl Signable for NonceResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_nonce_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }

        for nonce in &self.nonces {
            hasher.update(nonce.D.compress().as_bytes());
            hasher.update(nonce.E.compress().as_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignatureShareRequest {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub correlation_id: u64,
    pub nonce_responses: Vec<NonceResponse>,
    pub message: Vec<u8>,
}

impl Signable for SignatureShareRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.correlation_id.to_be_bytes());

        for nonce_response in &self.nonce_responses {
            nonce_response.hash(hasher);
        }

        hasher.update(self.message.as_slice());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignatureShareResponse {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub correlation_id: u64,
    pub signer_id: u32,
    pub signature_shares: Vec<SignatureShare>,
}

impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.correlation_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigShareRequestPox {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub correlation_id: u64,
    pub nonce_responses: Vec<NonceResponse>,
    pub message: Vec<u8>,
    pub transaction: Transaction,
}

impl Signable for SigShareRequestPox {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGSHARE_REQUEST_POX".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.correlation_id.to_be_bytes());

        for nonce_response in &self.nonce_responses {
            nonce_response.hash(hasher);
        }

        hasher.update(self.message.as_slice());
        hasher.update(bitcoin::psbt::serialize::Serialize::serialize(&self.transaction).as_slice());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigShareResponsePox {
    pub dkg_id: u64,
    pub sign_id: u64,
    pub correlation_id: u64,
    pub signer_id: u32,
    pub signature_shares: Vec<SignatureShare>,
}

impl Signable for SigShareResponsePox {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGSHARE_RESPONSE_POX".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.correlation_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VoteOutActorRequest {
    pub dkg_id: u64,
    pub aggregate_public_key: Point,
    pub actors_to_be_voted_out: Vec<StacksAddress>,
}

impl Signable for VoteOutActorRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DEGENS_CREATE_SCRIPT_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.aggregate_public_key.to_string().as_bytes());
        for actor in &self.actors_to_be_voted_out {
            hasher.update(actor.to_string().as_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DegensScriptRequest {
    pub dkg_id: u64,
    pub aggregate_public_key: Point,
}

impl Signable for DegensScriptRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DEGENS_CREATE_SCRIPT_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.aggregate_public_key.to_string().as_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DegensScriptResponse {
    pub signer_id: u32,
    pub stacks_address: StacksAddress,
    pub merkle_root: TapBranchHash,
    pub utxo: Result<UTXO, UtxoError>,
}

impl Signable for DegensScriptResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DEGENS_CREATE_SCRIPT_RESPONSE".as_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        hasher.update(self.stacks_address.bytes.as_bytes());
        hasher.update(self.stacks_address.version.to_be_bytes());

        hasher.update(self.merkle_root.to_vec().as_slice());

        match &self.utxo {
            Ok(utxo) => {
                hasher.update(utxo.address.as_bytes());
                hasher.update(utxo.txid.as_bytes());
                hasher.update(utxo.amount.to_be_bytes());
                hasher.update(utxo.desc.as_bytes());
                hasher.update(utxo.confirmations.to_be_bytes());
                hasher.update(utxo.label.as_bytes());
                hasher.update(utxo.redeemScript.as_bytes());
                hasher.update(utxo.reused.to_string().as_bytes());
                hasher.update(utxo.safe.to_string().as_bytes());
                hasher.update(utxo.scriptPubKey.as_bytes());
                hasher.update(utxo.solvable.to_string().as_bytes());
                hasher.update(utxo.spendable.to_string().as_bytes());
                hasher.update(utxo.vout.to_be_bytes());
                hasher.update(utxo.witnessScript.as_bytes());
            }
            Err(_) => {
                hasher.update("No good UTXO in the list.".as_bytes());
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DegensSpendScript {
    pub dkg_id: u64,
    pub addresses: Vec<String>, // TODO degens: update to address type/alias
}

impl Signable for DegensSpendScript {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DEGENS_SPEND_SCRIPT".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        for address in &self.addresses {
            hasher.update(address.as_bytes());
        }
    }
}

impl SigningRound {
    pub fn new(
        threshold: u32,
        total_signers: u32,
        total_keys: u32,
        signer_id: u32,
        key_ids: Vec<u32>,
        network_private_key: Scalar,
        public_keys: PublicKeys,
        network: Network,
    ) -> SigningRound {
        assert!(threshold <= total_keys);
        let mut rng = OsRng;
        let frost_signer = v1::Signer::new(signer_id, &key_ids, total_keys, threshold, &mut rng);
        let signer = Signer {
            frost_signer,
            signer_id,
        };

        SigningRound {
            dkg_id: 0,
            dkg_public_id: 0,
            sign_id: 1,
            sign_nonce_id: 1,
            threshold,
            total_signers,
            total_keys,
            signer,
            state: States::Idle,
            commitments: BTreeMap::new(),
            shares: HashMap::new(),
            public_nonces: vec![],
            network_private_key,
            public_keys,
            contract_name: ContractName::from(""),
            contract_address: StacksAddress::new(26, Hash160([0; 20])),
            aggregate_public_key: Point::new(),
            stacks_private_key: StacksPrivateKey::new(),
            stacks_address: StacksAddress::new(26, Hash160([0; 20])),
            stacks_node_rpc_url: Url::from_str("").unwrap(),
            local_stacks_node: NodeClient::new(
                Url::from_str("").unwrap(),
                ContractName::from(""),
                StacksAddress::new(26, Hash160([0; 20])),
            ),
            stacks_wallet: StacksWallet::new(
                ContractName::from(""),
                StacksAddress::from_string("").unwrap(),
                StacksPrivateKey::new(),
                StacksAddress::new(26, Hash160([0; 20])),
                TransactionVersion::Testnet,
                0,
            ),
            stacks_version: TransactionVersion::Testnet,
            bitcoin_private_key: SecretKey::new(&mut rng),
            bitcoin_xonly_public_key: SecretKey::new(&mut rng)
                .x_only_public_key(&Secp256k1::new())
                .0,
            bitcoin_node_rpc_url: Url::from_str("").unwrap(),
            local_bitcoin_node: LocalhostBitcoinNode::new(Url::from_str("").unwrap()),
            bitcoin_wallet: BitcoinWallet::new(
                XOnlyPublicKey::from_str(
                    "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                )
                    .unwrap(),
                network,
            ),
            transaction_fee: 0,
            bitcoin_network: network,
            script_addresses: BTreeMap::new(),
        }
    }

    fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.dkg_public_id = 0;
        self.commitments.clear();
        self.shares.clear();
        self.public_nonces.clear();
        self.signer.frost_signer.reset_polys(rng);
    }

    pub fn process(&mut self, message: MessageTypes) -> Result<Vec<MessageTypes>, Error> {
        let out_msgs = match message {
            MessageTypes::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin),
            MessageTypes::DkgPrivateBegin(_) => self.dkg_private_begin(),
            MessageTypes::DkgPublicShare(dkg_public_shares) => {
                self.dkg_public_share(dkg_public_shares)
            }
            MessageTypes::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares)
            }
            MessageTypes::SignShareRequest(sign_share_request) => {
                self.sign_share_request(sign_share_request)
            }
            MessageTypes::SigShareRequestPox(sigshare_request_pox) => {
                self.sigshare_request_pox(sigshare_request_pox)
            }
            MessageTypes::NonceRequest(nonce_request) => {
                self.nonce_request(nonce_request)
            },
            MessageTypes::VoteOutActorRequest(vote_out_request) => {
                self.vote_miners_out_of_pool(vote_out_request)
            }
            MessageTypes::DegensCreateScriptsRequest(degens_create_script) => {
                self.degen_create_script(degens_create_script)
            }

            _ => Ok(vec![]), // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.public_shares_done() {
                    debug!(
                        "public_shares_done==true. commitments {}",
                        self.commitments.len()
                    );
                    let dkg_end_msgs = self.dkg_public_ended()?;
                    out.push(dkg_end_msgs);
                    self.move_to(States::DkgPrivateDistribute)?;
                } else if self.can_dkg_end() {
                    debug!(
                        "can_dkg_end==true. shares {} commitments {}",
                        self.shares.len(),
                        self.commitments.len()
                    );
                    let dkg_end_msgs = self.dkg_ended()?;
                    out.push(dkg_end_msgs);
                    self.move_to(States::Idle)?;
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }

    fn dkg_public_ended(&mut self) -> Result<MessageTypes, Error> {
        let dkg_end = DkgEnd {
            dkg_id: self.dkg_id,
            signer_id: self.signer.signer_id,
            status: DkgStatus::Success,
        };
        let dkg_end = MessageTypes::DkgPublicEnd(dkg_end);
        info!(
            "DKG_END round #{} signer_id {}",
            self.dkg_id, self.signer.signer_id
        );
        Ok(dkg_end)
    }

    fn dkg_ended(&mut self) -> Result<MessageTypes, Error> {
        let polys: Vec<PolyCommitment> = self.commitments.clone().into_values().collect();

        let mut decrypted_shares = HashMap::new();

        // go through private shares, and decrypt any for owned keys, leaving the rest as zero scalars
        let key_ids: HashSet<u32> = self.signer.frost_signer.get_key_ids().into_iter().collect();
        let mut invalid_dkg_private_shares = Vec::new();

        for (src_key_id, encrypted_shares) in &self.shares {
            let mut decrypted_key_shares = HashMap::new();

            for (dst_key_id, private_share) in encrypted_shares {
                if key_ids.contains(dst_key_id) {
                    debug!(
                        "decrypting dkg private share for key_id #{}",
                        dst_key_id + 1
                    );
                    let compressed =
                        Compressed::from(self.public_keys.key_ids[&(src_key_id + 1)].to_bytes());
                    let src_public_key = Point::try_from(&compressed).unwrap();
                    let shared_secret =
                        make_shared_secret(&self.network_private_key, &src_public_key);

                    match decrypt(&shared_secret, private_share) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_key_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from key_id {} to key_id {}: {:?}", src_key_id, dst_key_id, e);
                                invalid_dkg_private_shares.push(*src_key_id);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from key_id {} to key_id {}: {:?}", src_key_id, dst_key_id, e);
                            invalid_dkg_private_shares.push(*src_key_id);
                        }
                    }
                } else {
                    decrypted_key_shares.insert(*dst_key_id, Scalar::new());
                }
            }

            decrypted_shares.insert(*src_key_id, decrypted_key_shares);
        }

        let dkg_end = if invalid_dkg_private_shares.is_empty() {
            match self
                .signer
                .frost_signer
                .compute_secrets(&decrypted_shares, &polys)
            {
                Ok(()) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer.signer_id,
                    status: DkgStatus::Success,
                },
                Err(dkg_error_map) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer.signer_id,
                    status: DkgStatus::Failure(format!("{:?}", dkg_error_map)),
                },
            }
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer.signer_id,
                status: DkgStatus::Failure(format!("{:?}", invalid_dkg_private_shares)),
            }
        };

        let dkg_end = MessageTypes::DkgEnd(dkg_end);
        info!(
            "DKG_END round #{} signer_id {}",
            self.dkg_id, self.signer.signer_id
        );
        Ok(dkg_end)
    }

    fn public_shares_done(&self) -> bool {
        debug!(
            "public_shares_done state {:?} commitments {}",
            self.state,
            self.commitments.len(),
        );
        self.state == States::DkgPublicGather
            && self.commitments.len() == usize::try_from(self.total_keys).unwrap()
    }

    fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end state {:?} commitments {} shares {}",
            self.state,
            self.commitments.len(),
            self.shares.len()
        );
        self.state == States::DkgPrivateGather
            && self.commitments.len() == usize::try_from(self.total_keys).unwrap()
            && self.shares.len() == usize::try_from(self.total_keys).unwrap()
    }

    fn nonce_request(&mut self, nonce_request: NonceRequest) -> Result<Vec<MessageTypes>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        let signer_id = self.signer.signer_id;
        let key_ids = self.signer.frost_signer.get_key_ids();
        let nonces = self.signer.frost_signer.gen_nonces(&mut rng);

        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_nonce_id: nonce_request.sign_nonce_id,
            signer_id,
            key_ids,
            nonces,
        };

        let response = MessageTypes::NonceResponse(response);

        info!(
            "nonce request with dkg_id {:?}. response sent from signer_id {}",
            nonce_request.dkg_id, signer_id
        );
        msgs.push(response);

        Ok(msgs)
    }

    fn sign_share_request(
        &mut self,
        sign_request: SignatureShareRequest,
    ) -> Result<Vec<MessageTypes>, Error> {
        let mut msgs = vec![];

        let signer_ids = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<Vec<u32>>();

        info!("Got SignatureShareRequest for signer_ids {:?}", signer_ids);

        for signer_id in &signer_ids {
            if *signer_id == self.signer.signer_id {
                let key_ids: Vec<u32> = sign_request
                    .nonce_responses
                    .iter()
                    .flat_map(|nr| nr.key_ids.iter().copied())
                    .collect::<Vec<u32>>();
                let nonces = sign_request
                    .nonce_responses
                    .iter()
                    .flat_map(|nr| nr.nonces.clone())
                    .collect::<Vec<PublicNonce>>();
                let signature_shares = self.signer.frost_signer.sign(
                    &sign_request.message,
                    &signer_ids,
                    &key_ids,
                    &nonces,
                );

                let response = SignatureShareResponse {
                    dkg_id: sign_request.dkg_id,
                    sign_id: sign_request.sign_id,
                    correlation_id: sign_request.correlation_id,
                    signer_id: *signer_id,
                    signature_shares,
                };

                info!(
                    "Sending SignatureShareResponse for signer_id {:?}",
                    signer_id
                );

                let response = MessageTypes::SignShareResponse(response);

                msgs.push(response);
            } else {
                debug!("SignShareRequest for {} dropped.", signer_id);
            }
        }
        Ok(msgs)
    }

    fn sigshare_request_pox(
        &mut self,
        sign_request: SigShareRequestPox,
    ) -> Result<Vec<MessageTypes>, Error> {
        let mut msgs = vec![];

        let secp = Secp256k1::new();
        let keypair = KeyPair::from_secret_key(&secp, &self.bitcoin_private_key);

        // let aggregate_compressed = degens_create_script.aggregate_public_key.compress();
        // let aggregate_x_only = PublicKey::from_slice(aggregate_compressed.as_bytes()).unwrap().to_x_only_pubkey();

        let script_1 = create_script_refund(&self.bitcoin_xonly_public_key, 100);
        let script_2 = create_script_unspendable();

        // TODO: degens - change keypair xonly back to aggregate_x_only after done with testing
        let (_, script_address) = create_tree(&secp, keypair.x_only_public_key().0, &script_1, &script_2);

        let transaction_clone = sign_request.transaction;
        let transaction_outputs = &transaction_clone.output;
        let transaction_inputs = &transaction_clone.input;

        let mut pox_addresses = vec![
            Address::from_str("bcrt1phvt5tfz4hlkth0k7ls9djweuv9rwv5a0s5sa9085umupftnyalxq0zx28d").unwrap(),
            Address::from_str("bcrt1pdsavc4yrdq0sdmjcmf7967eeem2ny6vzr4f8m7dyemcvncs0xtwsc85zdq").unwrap()
        ];
        let mut pox_total_amount: u64 = 0;
        let pox_sc_amount = self.local_stacks_node.get_pool_total_spend_per_block(self.stacks_wallet.address()).unwrap_or(0) as u64;

        transaction_outputs.iter().for_each(|output| {
            match Address::from_script(&output.script_pubkey, self.bitcoin_network) {
                Ok(address) => {
                    if pox_addresses.contains(&address) {
                        pox_addresses.retain(|user| user != &address);
                        pox_total_amount = pox_total_amount + output.value;
                    }
                }
                Err(e) => {
                    info!("Couldn't retreive address from UTXO: {:?}", e);
                }
            }
        });

        let script_utxos = self.local_bitcoin_node.list_unspent(&script_address).unwrap_or(vec![]);
        let mut found_utxo_in_inputs = false;

        for utxo in script_utxos {
            for input in transaction_inputs {
                if input.previous_output.txid.to_string() == utxo.txid && input.previous_output.vout == utxo.vout {
                    found_utxo_in_inputs = true;
                    break
                }
            }

            if found_utxo_in_inputs {
                break
            }
        }

        if pox_addresses.len() == 0 && pox_total_amount == pox_sc_amount && found_utxo_in_inputs {
            let signer_ids = sign_request
                .nonce_responses
                .iter()
                .map(|nr| nr.signer_id)
                .collect::<Vec<u32>>();

            info!("Got SigShareRequestPox for signer_ids {:?}", signer_ids);

            for signer_id in &signer_ids {
                if *signer_id == self.signer.signer_id {
                    let key_ids: Vec<u32> = sign_request
                        .nonce_responses
                        .iter()
                        .flat_map(|nr| nr.key_ids.iter().copied())
                        .collect::<Vec<u32>>();
                    let nonces = sign_request
                        .nonce_responses
                        .iter()
                        .flat_map(|nr| nr.nonces.clone())
                        .collect::<Vec<PublicNonce>>();
                    let signature_shares = self.signer.frost_signer.sign(
                        &sign_request.message,
                        &signer_ids,
                        &key_ids,
                        &nonces,
                    );

                    let response = SigShareResponsePox {
                        dkg_id: sign_request.dkg_id,
                        sign_id: sign_request.sign_id,
                        correlation_id: sign_request.correlation_id,
                        signer_id: *signer_id,
                        signature_shares,
                    };

                    info!(
                    "Sending SigShareResponsePox for signer_id {:?}",
                    signer_id
                );

                    let response = MessageTypes::SigShareResponsePox(response);

                    msgs.push(response);
                } else {
                    debug!("SigShareRequestPox for {} dropped.", signer_id);
                }
            }
        }
        else {
            let cause = if pox_addresses.len() != 0 {
                "The transaction did not contain the correct PoX addresses!"
            } else if pox_total_amount != pox_sc_amount {
                "The transaction did not contain the correct amount!"
            } else if !found_utxo_in_inputs {
                "Could not find your script's UTXO as input in the transaction!"
            } else {
                "" // Never coming on this branch, it always is one of the above.
            };

            info!("The signing failed: {:?}", cause);

            let log_directory = std::path::Path::new("../degen-base-signer/logs/");

            if !log_directory.exists() {
                if let Err(e) = std::fs::create_dir_all(&log_directory) {
                    info!("Failed to create directory: {:?}", e);
                }
            }

            let file_path = log_directory.join(format!("malicious_coordinator_signer_{:?}.txt", self.signer.signer_id));

            let formatted_date_time = Local::now().format("%d-%m-%Y - %H:%M:%S").to_string();

            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path) {
                Ok(mut file) => {
                    let log_message = format!("\
                    Date and time: {:?}\n\
                    Cause: {:#?}\n\
                    Block height: {:#?}\n\
                    {:#?}\n\n\
                    ============================================\n\n", formatted_date_time, cause, get_current_block_height(&self.local_bitcoin_node.clone()), transaction_clone);

                    if let Err(e) = file.write_all(log_message.as_bytes()) {
                        info!("Couldn't write to file: {:?}", e)
                    }

                    if let Err(e) = file.flush() {
                        info!("Couldn't flush the file: {:?}", e)
                    }
                }
                Err(e) => {
                    info!("Couldn't create log file: {:?}", e);
                }
            }
        }
        Ok(msgs)
    }

    fn dkg_begin(&mut self, dkg_begin: DkgBegin) -> Result<Vec<MessageTypes>, Error> {
        let mut rng = OsRng;

        self.reset(dkg_begin.dkg_id, &mut rng);
        self.move_to(States::DkgPublicDistribute)?;

        let _party_state = self.signer.frost_signer.save();

        self.dkg_public_begin()
    }

    fn dkg_public_begin(&mut self) -> Result<Vec<MessageTypes>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        let polys = self.signer.frost_signer.get_poly_commitments(&mut rng);

        info!(
            "sending DkgPublicShares for round #{}, {} poly commitments for signer #{}",
            self.dkg_id,
            polys.len(),
            self.signer.frost_signer.get_id(),
        );

        for poly in &polys {
            let public_share = DkgPublicShare {
                dkg_id: self.dkg_id,
                dkg_public_id: self.dkg_public_id,
                party_id: poly.id.id.get_u32(),
                public_share: poly.clone(),
            };

            let public_share = MessageTypes::DkgPublicShare(public_share);
            msgs.push(public_share);
        }

        self.move_to(States::DkgPublicGather)?;
        Ok(msgs)
    }

    fn dkg_private_begin(&mut self) -> Result<Vec<MessageTypes>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        for (key_id, private_shares) in &self.signer.frost_signer.get_shares() {
            info!(
                "signer {} sending dkg private share for key_id #{}",
                self.signer.signer_id, key_id
            );
            // encrypt each share for the recipient
            let mut encrypted_shares = HashMap::new();

            for (dst_key_id, private_share) in private_shares {
                debug!(
                    "encrypting dkg private share for key_id #{}",
                    dst_key_id + 1
                );
                let compressed =
                    Compressed::from(self.public_keys.key_ids[&(dst_key_id + 1)].to_bytes());
                let dst_public_key = Point::try_from(&compressed).unwrap();
                let shared_secret = make_shared_secret(&self.network_private_key, &dst_public_key);
                let encrypted_share =
                    encrypt(&shared_secret, &private_share.to_bytes(), &mut rng).unwrap();

                encrypted_shares.insert(*dst_key_id, encrypted_share);
            }

            let private_shares = DkgPrivateShares {
                dkg_id: self.dkg_id,
                key_id: *key_id,
                private_shares: encrypted_shares,
            };

            let private_shares = MessageTypes::DkgPrivateShares(private_shares);
            msgs.push(private_shares);
        }

        self.move_to(States::DkgPrivateGather)?;
        Ok(msgs)
    }

    fn dkg_public_share(
        &mut self,
        dkg_public_share: DkgPublicShare,
    ) -> Result<Vec<MessageTypes>, Error> {
        self.commitments
            .insert(dkg_public_share.party_id, dkg_public_share.public_share);
        info!(
            "received DkgPublicShare from key #{} {}/{}",
            dkg_public_share.party_id,
            self.commitments.len(),
            self.total_keys
        );
        Ok(vec![])
    }

    fn dkg_private_shares(
        &mut self,
        dkg_private_shares: DkgPrivateShares,
    ) -> Result<Vec<MessageTypes>, Error> {
        let shares_clone = dkg_private_shares.private_shares.clone();
        self.shares
            .insert(dkg_private_shares.key_id, dkg_private_shares.private_shares);
        info!(
            "received DkgPrivateShares from key #{} {}/{} {:?}",
            dkg_private_shares.key_id,
            self.shares.len(),
            self.total_keys,
            shares_clone.keys(),
        );
        Ok(vec![])
    }

    fn vote_miners_out_of_pool(
        &mut self,
        vote_out_request: VoteOutActorRequest,
    ) -> Result<Vec<MessageTypes>, Error> {
        let mut node_clone = self.local_stacks_node.clone();
        let mut wallet_clone = self.stacks_wallet.clone();
        let mut nonce = self.local_stacks_node.next_nonce(&self.stacks_wallet.address()).unwrap_or(0);

        thread::spawn(move || {
            let mut actors_to_be_voted_out = vote_out_request.actors_to_be_voted_out.clone();
            loop {
                for actor in actors_to_be_voted_out.clone() {
                    match node_clone.clone().get_miners_list(wallet_clone.address()) {
                        Ok(miners_list) => {
                            if miners_list.contains(&actor) {
                                match node_clone.clone().is_proposed_for_removal(wallet_clone.address(), &actor) {
                                    Ok(value) => {
                                        if value == true {
                                            match wallet_clone.vote_positive_remove_request(nonce, actor) {
                                                Ok(tx) => {
                                                    match node_clone.broadcast_transaction(&tx) {
                                                        Ok(()) => {
                                                            info!("Successfully voted out {:?}", actor.to_string());
                                                            actors_to_be_voted_out.retain(|user| user != &actor);
                                                            nonce += 1;
                                                        }
                                                        Err(e) => {
                                                            info!("Error broadcasting the voting out transaction for {:?}: {:?}", actor.to_string(), e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    info!("Couldn't make vote out transaction for {:?}: {:?}", &actor.to_string(), e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("Could not check if {:?} is proposed for removal.", actor.to_string());
                                    }
                                }
                            }
                            else {
                                actors_to_be_voted_out.retain(|user| user != &actor);
                            }
                        }
                        Err(e) => {
                            info!("Couldn't get miner's list: {:?}", e)
                        }
                    }
                }
                if actors_to_be_voted_out.len() == 0 {
                    break
                }
                sleep(Duration::from_secs(300));
            }
        });

        Ok(vec![])
    }

    fn degen_create_script(
        &mut self,
        degens_create_script: DegensScriptRequest,
    ) -> Result<Vec<MessageTypes>, Error> {
        // let current_block_height = get_current_block_height(&self.local_bitcoin_node);
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_secret_key(&secp, &self.bitcoin_private_key);

        let aggregate_compressed = degens_create_script.aggregate_public_key.compress();
        let aggregate_x_only = PublicKey::from_slice(aggregate_compressed.as_bytes()).unwrap().to_x_only_pubkey();

        let script_1 = create_script_refund(&self.bitcoin_xonly_public_key, 100);
        let script_2 = create_script_unspendable();

        let (tap_info, script_address) = create_tree(&secp, aggregate_x_only, &script_1, &script_2);

        let amount_to_script: u64 = self.local_stacks_node.get_pool_total_spend_per_block(self.stacks_wallet.address()).expect("Failed to retreive amount to script") as u64 / self.local_stacks_node.get_miners_list(&self.stacks_wallet.address()).expect("Failed to receive miners list!").len() as u64;
        let fee: u64 = 300;

        let mut unspent_list_signer = self
            .local_bitcoin_node
            .list_unspent(&self.bitcoin_wallet.address())
            .unwrap_or(vec![]);

        let mut valid_utxos = vec![];
        let mut total_amount: u64 = 0;

        // This works, but we have no confirmations because of the node not mining blocks
        // Switch back to it once the issue is fixed
        // unspent_list_signer.sort_by(|a, b| b.confirmations.partial_cmp(&a.confirmations).unwrap());
        unspent_list_signer.sort_by(|a, b| b.amount.partial_cmp(&a.amount).unwrap());
        for utxo in unspent_list_signer.clone() {
            if total_amount < amount_to_script + fee {
                total_amount += utxo.amount;
                valid_utxos.push(utxo);
            }
        }

        if total_amount < amount_to_script + fee {
            valid_utxos = vec![];
            total_amount = 0;
        }

        if valid_utxos == vec![] {
            return Err(Error::UTXOAmount);
        }

        let mut unspent_list_txout: Vec<TxOut> = vec![];
        valid_utxos.iter().for_each(|utxo| {
            unspent_list_txout.push(TxOut {
                value: utxo.amount,
                script_pubkey: Script::from_str(utxo.scriptPubKey.as_str()).unwrap(),
            });
        });

        let prevouts_signer = Prevouts::All(unspent_list_txout.as_slice());

        if total_amount < amount_to_script + fee {
            info!("You don't have enough money to fund the script!");
            return Err(Error::UTXOAmount);
        }

        let user_to_script_unsigned = create_tx_from_user_to_script(
            &valid_utxos,
            &self.bitcoin_wallet.address(),
            &script_address,
            amount_to_script,
            fee,
        );

        let user_to_script_signed = sign_tx_user_to_script(&secp, &user_to_script_unsigned, &prevouts_signer, &keypair);

        match self.local_bitcoin_node.broadcast_transaction(&user_to_script_signed) {
            Ok(txid) => {
                info!("Succesfully funded script. Txid: {:?}", txid)
            }
            Err(e) => {
                info!("Couldn't broadcast fund script transaction: {:?}", e)
            }
        };

        if self.local_bitcoin_node.list_descriptors().unwrap_or(vec![]).contains(&script_address) == false {
            loop {
                let mut number_of_iterations = 0;
                match self.local_bitcoin_node.load_wallet(&script_address) {
                    Ok(()) => {
                        break
                    }
                    Err(e) => {
                        if number_of_iterations % 10 == 0 {
                            info!("Couldn't load script address: {:?}", e)
                        }
                        // How many times to try loading the script address
                        if number_of_iterations == 100 {
                            break
                        }
                    }
                }
                number_of_iterations += 1;
                sleep(Duration::from_secs((1)));
            }
        }

        let utxos = self.local_bitcoin_node.list_unspent(&script_address).unwrap_or(vec![]);

        let mut txout_vec: Vec<TxOut> = vec![];
        utxos.iter().for_each(|utxo| {
            txout_vec.push(TxOut {
                value: utxo.amount,
                script_pubkey: Script::from_str(utxo.scriptPubKey.as_str()).unwrap(),
            });
        });

        let good_utxo = get_good_utxo_from_list(utxos, amount_to_script);

        let mut msgs = vec![];

        let response = DegensScriptResponse {
            signer_id: self.signer.signer_id,
            stacks_address: self.stacks_address,
            merkle_root: tap_info.merkle_root().unwrap(),
            utxo: good_utxo,
        };

        let response = MessageTypes::DegensCreateScriptsResponse(response);
        msgs.push(response);

        Ok(msgs)

        // let current_block_height = get_current_block_height(&self.local_bitcoin_node);
        // let secp = Secp256k1::new();
        // let keypair = KeyPair::from_secret_key(&secp, &self.bitcoin_private_key);
        //
        // let aggregate_compressed = degens_create_script.aggregate_public_key.compress();
        // let aggregate_x_only = PublicKey::from_slice(aggregate_compressed.as_bytes()).unwrap().to_x_only_pubkey();
        //
        // let script_1 = create_script_refund(&self.bitcoin_xonly_public_key, 100);
        // let script_2 = create_script_unspendable();
        //
        // // TODO: degens - change keypair xonly back to aggregate_x_only after done with testing
        // let (tap_info, script_address) = create_tree(&secp, keypair.x_only_public_key().0, self.bitcoin_network, &script_1, &script_2);
        //
        // // TODO: check this, if it's true all good, if it's not then there was an issue in one of the previous transactions
        // let are_previous_transactions_good = self.check_if_transaction_is_good(&script_address);
        //
        // let amount_to_pox = self.local_stacks_node.get_pool_total_spend_per_block(self.stacks_wallet.address()).unwrap_or(0) as u64 / self.local_stacks_node.get_miners_list(&self.stacks_wallet.address()).unwrap_or(vec![self.stacks_address]).len() as u64;
        // let amount_to_script: u64 = self.amount_to_script;
        // let user_to_script_fee: u64 = 300;
        //
        // let mut script_utxo: Result<UTXO, UtxoError> = Err(InvalidUTXO);
        // let mut script_address_needs_funds = true;
        //
        // let imported_addresses = self.local_bitcoin_node.list_descriptors().unwrap_or(vec![]);
        //
        // if imported_addresses.contains(&script_address) == false {
        //     let mut number_of_iterations = 0;
        //     loop {
        //         match self.local_bitcoin_node.load_wallet(&script_address) {
        //             Ok(()) => {
        //                 break
        //             }
        //             Err(e) => {
        //                 if number_of_iterations % 10 == 0 {
        //                     info!("Couldn't load script address: {:?}", e)
        //                 }
        //                 // How many times to try loading the script address
        //                 if number_of_iterations == 100 {
        //                     break
        //                 }
        //             }
        //         }
        //         number_of_iterations += 1;
        //         sleep(Duration::from_secs((1)));
        //     }
        // }
        //
        // let script_utxos = self.local_bitcoin_node.list_unspent(&script_address).unwrap_or(vec![]);
        // let mut run_refund_phase = false;
        //
        // let total_amount = self.local_stacks_node.get_pool_total_spend_per_block(self.stacks_wallet.address()).unwrap_or(0) as u64;
        // let fee = 1000;
        // let number_of_signers = self.local_stacks_node.get_miners_list(&self.stacks_wallet.address()).unwrap_or(vec![self.stacks_wallet.address().clone()]).len() as u64;
        //
        // for utxo in &script_utxos {
        //     if amount_to_pox <= utxo.amount {
        //         script_utxo = Ok(utxo.clone());
        //         script_address_needs_funds = false;
        //         let amount_back = utxo.amount - ((total_amount + fee) / number_of_signers);
        //         self.amount_back_to_script.push((current_block_height, amount_back));
        //     }
        //     else {
        //         script_utxo = Err(InvalidUTXO);
        //         run_refund_phase = true;
        //     }
        // }
        //
        // if run_refund_phase {
        //     let mut amount_to_refund: u64 = 0;
        //
        //     for utxo in &script_utxos {
        //         amount_to_refund += utxo.amount;
        //     }
        //
        //     if amount_to_refund > user_to_script_fee {
        //         amount_to_refund -= user_to_script_fee;
        //
        //         let refund_tx = create_refund_tx(&script_utxos, self.bitcoin_wallet.address(), amount_to_refund);
        //
        //         let mut txout_vec: Vec<TxOut> = vec![];
        //         script_utxos.iter().for_each(|utxo| {
        //             txout_vec.push(TxOut {
        //                 value: utxo.amount,
        //                 script_pubkey: Script::from_str(utxo.scriptPubKey.as_str()).unwrap(),
        //             });
        //         });
        //
        //         let signed_refund_tx = sign_tx_script_refund(&secp, &refund_tx, &txout_vec, &script_1, &keypair, &tap_info);
        //
        //         match self.local_bitcoin_node.broadcast_transaction(&signed_refund_tx) {
        //             Ok(txid) => {
        //                 info!("Succesfully refunded money. Txid: {:?}", txid)
        //             }
        //             Err(e) => {
        //                 info!("Couldn't broadcast refund transaction: {:?}", e)
        //             }
        //         };
        //     }
        //     else {
        //         info!("You don't have enough money to refund from script address!")
        //     }
        // }
        //
        // if script_address_needs_funds == true {
        //     info!("Not enough money on script. Running the funding phase!");
        //
        //     let mut unspent_list_signer = self
        //         .local_bitcoin_node
        //         .list_unspent(&self.bitcoin_wallet.address())
        //         .unwrap_or(vec![]);
        //
        //     let mut valid_utxos = vec![];
        //     let mut total_amount: u64 = 0;
        //
        //     // This works, but we have no confirmations because of the node not mining blocks
        //     // Switch back to it once the issue is fixed
        //     // unspent_list_signer.sort_by(|a, b| b.confirmations.partial_cmp(&a.confirmations).unwrap());
        //
        //     if &unspent_list_signer.len() > &2 {
        //         unspent_list_signer.sort_by(|a, b| b.amount.partial_cmp(&a.amount).unwrap());
        //     }
        //
        //     for utxo in &unspent_list_signer {
        //         if total_amount < amount_to_script + user_to_script_fee {
        //             total_amount += utxo.amount;
        //             valid_utxos.push(utxo.clone());
        //             continue
        //         }
        //         break
        //     }
        //
        //     if total_amount < amount_to_script + user_to_script_fee {
        //         info!("You don't have enough money to fund the script!");
        //         script_utxo = Err(UTXOAmount);
        //     }
        //     else {
        //         let mut unspent_list_txout: Vec<TxOut> = vec![];
        //         valid_utxos.iter().for_each(|utxo| {
        //             unspent_list_txout.push(TxOut {
        //                 value: utxo.amount,
        //                 script_pubkey: Script::from_str(utxo.scriptPubKey.as_str()).unwrap(),
        //             });
        //         });
        //
        //         let prevouts_signer = Prevouts::All(unspent_list_txout.as_slice());
        //
        //         let user_to_script_unsigned = create_tx_from_user_to_script(
        //             &valid_utxos,
        //             &self.bitcoin_wallet.address(),
        //             &script_address,
        //             amount_to_script,
        //             user_to_script_fee,
        //         );
        //
        //         let user_to_script_signed =
        //             sign_tx_user_to_script(&secp, &user_to_script_unsigned, &prevouts_signer, &keypair);
        //
        //         match self.local_bitcoin_node.broadcast_transaction(&user_to_script_signed) {
        //             Ok(txid) => {
        //                 info!("Succesfully funded script. Txid: {:?}", txid)
        //             }
        //             Err(e) => {
        //                 info!("Couldn't broadcast fund script transaction: {:?}", e)
        //             }
        //         };
        //
        //         for utxo in self.local_bitcoin_node.list_unspent(&script_address).unwrap_or(vec![]) {
        //             if amount_to_pox <= utxo.amount {
        //                 let amount_back = utxo.amount - ((total_amount + fee) / number_of_signers);
        //                 self.amount_back_to_script.push((current_block_height, amount_back));
        //                 script_utxo = Ok(utxo);
        //             } else {
        //                 script_utxo = Err(InvalidUTXO);
        //             }
        //         }
        //     }
        // }
        //
        // if script_utxo.is_err() {
        //     info!("Couldn't get any valid transaction from script!");
        // }
        // else {
        //     info!("Found a good UTXO from script!");
        // }
        //
        // let mut msgs = vec![];
        //
        // let response = DegensScriptResponse {
        //     signer_id: self.signer.signer_id,
        //     stacks_address: self.stacks_address,
        //     merkle_root: tap_info.merkle_root().unwrap(),
        //     utxo: script_utxo,
        // };
        //
        // let response = MessageTypes::DegensCreateScriptsResponse(response);
        // msgs.push(response);
        //
        // Ok(msgs)
    }
}

impl From<&FrostSigner> for SigningRound {
    fn from(signer: &FrostSigner) -> Self {
        let signer_id = signer.signer_id;
        let signer_private_key = signer.config.stacks_private_key;
        assert!(signer_id > 0 && signer_id <= signer.config.total_signers);
        let key_ids = signer.config.signer_key_ids[&signer_id]
            .iter()
            .map(|i| i - 1)
            .collect::<Vec<u32>>();

        assert!(signer.config.keys_threshold <= signer.config.total_keys);
        let mut rng = OsRng;
        let frost_signer = v1::Signer::new(
            signer_id,
            &key_ids,
            signer.config.total_keys,
            signer.config.keys_threshold,
            &mut rng,
        );

        let network_private_key = signer.config.network_private_key;
        let public_keys = signer.config.public_keys.clone();

        SigningRound {
            dkg_id: 1,
            dkg_public_id: 1,
            sign_id: 1,
            sign_nonce_id: 1,
            threshold: signer.config.keys_threshold,
            total_keys: signer.config.total_keys,
            total_signers: signer.config.total_signers,
            signer: Signer {
                frost_signer,
                signer_id,
            },
            state: States::Idle,
            commitments: BTreeMap::new(),
            shares: HashMap::new(),
            public_nonces: vec![],
            network_private_key,
            public_keys,
            contract_name: signer.config.contract_name.clone(),
            contract_address: signer.config.contract_address,
            aggregate_public_key: Point::new(),
            stacks_private_key: signer.config.stacks_private_key,
            stacks_address: signer.config.stacks_address,
            stacks_node_rpc_url: signer.config.stacks_node_rpc_url.clone(),
            local_stacks_node: signer.config.local_stacks_node.clone(),
            stacks_wallet: signer.config.stacks_wallet.clone(),
            stacks_version: signer.config.stacks_version,
            bitcoin_private_key: signer.config.bitcoin_private_key,
            bitcoin_xonly_public_key: signer.config.bitcoin_xonly_public_key,
            bitcoin_node_rpc_url: signer.config.bitcoin_node_rpc_url.clone(),
            local_bitcoin_node: signer.config.local_bitcoin_node.clone(),
            bitcoin_wallet: signer.config.bitcoin_wallet.clone(),
            transaction_fee: signer.config.transaction_fee,
            bitcoin_network: signer.config.bitcoin_network,
            script_addresses: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::Network;
    use hashbrown::HashMap;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use wsts::{common::PolyCommitment, schnorr::ID, Scalar};

    use crate::signing_round::{
        DkgPrivateShares, DkgPublicShare, DkgStatus, MessageTypes, SigningRound,
    };
    use crate::state_machine::States;

    fn get_rng() -> impl RngCore + CryptoRng {
        let rnd = OsRng;
        //rand::rngs::StdRng::seed_from_u64(rnd.next_u64()) // todo: fix trait `rand_core::RngCore` is not implemented for `StdRng`
        rnd
    }

    #[test]
    fn dkg_public_share() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default(), Network::Regtest);
        let public_share = DkgPublicShare {
            dkg_id: 0,
            party_id: 0,
            public_share: PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                A: vec![],
            },
            dkg_public_id: 0,
        };
        signing_round.dkg_public_share(public_share).unwrap();
        assert_eq!(1, signing_round.commitments.len())
    }

    #[test]
    fn dkg_private_shares() {
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default(), Network::Regtest);
        let mut private_shares = DkgPrivateShares {
            dkg_id: 0,
            key_id: 0,
            private_shares: HashMap::new(),
        };
        private_shares.private_shares.insert(1, Vec::new());
        signing_round.dkg_private_shares(private_shares).unwrap();
        assert_eq!(1, signing_round.shares.len())
    }

    #[test]
    fn public_shares_done() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default(), Network::Regtest);
        // publich_shares_done starts out as false
        assert_eq!(false, signing_round.public_shares_done());

        // meet the conditions for all public keys received
        signing_round.state = States::DkgPublicGather;
        signing_round.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                A: vec![],
            },
        );

        // public_shares_done should be true
        assert!(signing_round.public_shares_done());
    }

    #[test]
    fn can_dkg_end() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default(), Network::Regtest);
        // can_dkg_end starts out as false
        assert_eq!(false, signing_round.can_dkg_end());

        // meet the conditions for DKG_END
        signing_round.state = States::DkgPrivateGather;
        signing_round.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                A: vec![],
            },
        );
        let shares: HashMap<u32, Vec<u8>> = HashMap::new();
        signing_round.shares.insert(1, shares);

        // can_dkg_end should be true
        assert!(signing_round.can_dkg_end());
    }

    #[test]
    fn dkg_ended() {
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default(), Network::Regtest);
        match signing_round.dkg_ended() {
            Ok(dkg_end) => match dkg_end {
                MessageTypes::DkgEnd(dkg_end) => match dkg_end.status {
                    DkgStatus::Failure(_) => assert!(true),
                    _ => assert!(false),
                },
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }
}
