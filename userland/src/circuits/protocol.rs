use ark_bw6_761::BW6_761;
use serde::{Deserialize, Serialize};

use ark_std::io::Cursor;
use ark_ec::pairing::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_groth16::*;

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::collaborative_snark::*;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::{
    JZVectorCommitment as JubJubVectorCommitment,
    JZVectorCommitmentOpeningProof as JubJubVectorCommitmentOpeningProof,
    JZVectorCommitmentPath as JubJubVectorCommitmentPath,
    JZVectorCommitmentLeafDigest as JubJubVectorCommitmentLeafDigest,
    JZVectorCommitmentInnerDigest as JubJubVectorCommitmentInnerDigest
};
use lib_mpc_zexe::vector_commitment::bytes::sha256::{
    JZVectorCommitment as Sha2VectorCommitment,
    JZVectorCommitmentOpeningProof as Sha2VectorCommitmentOpeningProof,
    JZVectorCommitmentPath as Sha2VectorCommitmentPath,
    JZVectorCommitmentLeafDigest as Sha2VectorCommitmentLeafDigest,
    JZVectorCommitmentInnerDigest as Sha2VectorCommitmentInnerDigest
};

type Curve = ark_bls12_377::Bls12_377;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type ConstraintF = ark_bw6_761::Fr;
type ConstraintPairing = ark_bw6_761::BW6_761;
type MTEdOnBls12_377 = lib_mpc_zexe::vector_commitment::bytes::pedersen::config::ed_on_bls12_377::MerkleTreeParams;
type MTEdOnBw6_761 = lib_mpc_zexe::vector_commitment::bytes::pedersen::config::ed_on_bw6_761::MerkleTreeParams;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VectorCommitmentOpeningProofBs58 {
    pub path_leaf_sibling_hash: String,
    pub path_auth_path: Vec<String>,
    pub path_leaf_index: usize,
    pub record: String,
    pub root: String
 }

 #[allow(non_snake_case)]
 pub fn jubjub_vector_commitment_opening_proof_MTEdOnBw6_761_to_bs58(
    proof: &JubJubVectorCommitmentOpeningProof<MTEdOnBw6_761, G1Affine>
 ) -> VectorCommitmentOpeningProofBs58 {
    let mut buffer: Vec<u8> = Vec::new();
    proof.path.leaf_sibling_hash.serialize_compressed(&mut buffer).unwrap();
    let path_leaf_sibling_hash = bs58::encode(buffer).into_string();

    let mut path_auth_path = Vec::new();
    for inner_digest in proof.path.auth_path.iter() {
        let mut buffer: Vec<u8> = Vec::new();
        inner_digest.serialize_compressed(&mut buffer).unwrap();
        let inner_digest_serialized = bs58::encode(buffer).into_string();

        path_auth_path.push(inner_digest_serialized);
    }

    let mut buffer: Vec<u8> = Vec::new();
    proof.record.serialize_compressed(&mut buffer).unwrap();
    let record = bs58::encode(buffer).into_string();

    let mut buffer: Vec<u8> = Vec::new();
    proof.root.serialize_compressed(&mut buffer).unwrap();
    let root = bs58::encode(buffer).into_string();

    VectorCommitmentOpeningProofBs58 {
        path_leaf_sibling_hash,
        path_auth_path,
        path_leaf_index: proof.path.leaf_index,
        record,
        root
    }
}

#[allow(non_snake_case)]
pub fn jubjub_vector_commitment_opening_proof_MTEdOnBls12_377_to_bs58(
    proof: &JubJubVectorCommitmentOpeningProof<MTEdOnBls12_377, G1Affine>
 ) -> VectorCommitmentOpeningProofBs58 {
    let mut buffer: Vec<u8> = Vec::new();
    proof.path.leaf_sibling_hash.serialize_compressed(&mut buffer).unwrap();
    let path_leaf_sibling_hash = bs58::encode(buffer).into_string();

    let mut path_auth_path = Vec::new();
    for inner_digest in proof.path.auth_path.iter() {
        let mut buffer: Vec<u8> = Vec::new();
        inner_digest.serialize_compressed(&mut buffer).unwrap();
        let inner_digest_serialized = bs58::encode(buffer).into_string();

        path_auth_path.push(inner_digest_serialized);
    }

    let mut buffer: Vec<u8> = Vec::new();
    proof.record.serialize_compressed(&mut buffer).unwrap();
    let record = bs58::encode(buffer).into_string();

    let mut buffer: Vec<u8> = Vec::new();
    proof.root.serialize_compressed(&mut buffer).unwrap();
    let root = bs58::encode(buffer).into_string();

    VectorCommitmentOpeningProofBs58 {
        path_leaf_sibling_hash,
        path_auth_path,
        path_leaf_index: proof.path.leaf_index,
        record,
        root
    }
}


 pub fn sha2_vector_commitment_opening_proof_to_bs58(
    proof: &Sha2VectorCommitmentOpeningProof<Vec<u8>>
 ) -> VectorCommitmentOpeningProofBs58 {
    let mut buffer: Vec<u8> = Vec::new();
    proof.path.leaf_sibling_hash.serialize_compressed(&mut buffer).unwrap();
    let path_leaf_sibling_hash = bs58::encode(buffer).into_string();

    let mut path_auth_path = Vec::new();
    for inner_digest in proof.path.auth_path.iter() {
        let mut buffer: Vec<u8> = Vec::new();
        inner_digest.serialize_compressed(&mut buffer).unwrap();
        let inner_digest_serialized = bs58::encode(buffer).into_string();

        path_auth_path.push(inner_digest_serialized);
    }

    let mut buffer: Vec<u8> = Vec::new();
    proof.record.serialize_compressed(&mut buffer).unwrap();
    let record = bs58::encode(buffer).into_string();

    let mut buffer: Vec<u8> = Vec::new();
    proof.root.serialize_compressed(&mut buffer).unwrap();
    let root = bs58::encode(buffer).into_string();

    VectorCommitmentOpeningProofBs58 {
        path_leaf_sibling_hash,
        path_auth_path,
        path_leaf_index: proof.path.leaf_index,
        record,
        root
    }
}

pub fn sha2_vector_commitment_opening_proof_from_bs58(
    proof: &VectorCommitmentOpeningProofBs58
) -> Sha2VectorCommitmentOpeningProof<Vec<u8>> {

    let buf: Vec<u8> = bs58::decode(proof.path_leaf_sibling_hash.clone()).into_vec().unwrap();
    let leaf_digest = Sha2VectorCommitmentLeafDigest::deserialize_compressed(buf.as_slice()).unwrap();

    let mut nodes: Vec<Sha2VectorCommitmentInnerDigest> = vec![];
    for node in proof.path_auth_path.iter() {
        let buf: Vec<u8> = bs58::decode(node.clone()).into_vec().unwrap();
        let node = Sha2VectorCommitmentInnerDigest::deserialize_compressed(buf.as_slice()).unwrap();

        nodes.push(node);
    }

    let buf: Vec<u8> = bs58::decode(proof.record.clone()).into_vec().unwrap();
    let record = Sha2VectorCommitment::deserialize_compressed(buf.as_slice()).unwrap();

    let buf: Vec<u8> = bs58::decode(proof.root.clone()).into_vec().unwrap();
    let root = Sha2VectorCommitment::deserialize_compressed(buf.as_slice()).unwrap();

    Sha2VectorCommitmentOpeningProof::<Vec<u8>> {
        path: Sha2VectorCommitmentPath {
            leaf_sibling_hash: leaf_digest,
            auth_path: nodes,
            leaf_index: proof.path_leaf_index,
        },
        record,
        root,
    }
}

#[allow(non_snake_case)]
pub fn jubjub_vector_commitment_opening_proof_MTEdOnBw6_761_from_bs58(
    proof: &VectorCommitmentOpeningProofBs58
) -> JubJubVectorCommitmentOpeningProof<MTEdOnBw6_761, G1Affine> {

    let buf: Vec<u8> = bs58::decode(proof.path_leaf_sibling_hash.clone()).into_vec().unwrap();
    let leaf_digest = JubJubVectorCommitmentLeafDigest::<MTEdOnBw6_761>::deserialize_compressed(buf.as_slice()).unwrap();

    let mut nodes: Vec<JubJubVectorCommitmentInnerDigest<MTEdOnBw6_761>> = vec![];
    for node in proof.path_auth_path.iter() {
        let buf: Vec<u8> = bs58::decode(node.clone()).into_vec().unwrap();
        let node = JubJubVectorCommitmentInnerDigest::<MTEdOnBw6_761>::deserialize_compressed(buf.as_slice()).unwrap();

        nodes.push(node);
    }

    let buf: Vec<u8> = bs58::decode(proof.record.clone()).into_vec().unwrap();
    let record = G1Affine::deserialize_compressed(buf.as_slice()).unwrap();

    let buf: Vec<u8> = bs58::decode(proof.root.clone()).into_vec().unwrap();
    let root = JubJubVectorCommitment::<MTEdOnBw6_761>::deserialize_compressed(buf.as_slice()).unwrap();

    JubJubVectorCommitmentOpeningProof {
        path: JubJubVectorCommitmentPath {
            leaf_sibling_hash: leaf_digest,
            auth_path: nodes,
            leaf_index: proof.path_leaf_index,
        },
        record,
        root,
    }
}

#[allow(non_snake_case)]
pub fn jubjub_vector_commitment_opening_proof_MTEdOnBls12_377_from_bs58(
    proof: &VectorCommitmentOpeningProofBs58
) -> JubJubVectorCommitmentOpeningProof<MTEdOnBls12_377, G1Affine> {

    let buf: Vec<u8> = bs58::decode(proof.path_leaf_sibling_hash.clone()).into_vec().unwrap();
    let leaf_digest = JubJubVectorCommitmentLeafDigest::<MTEdOnBls12_377>::deserialize_compressed(buf.as_slice()).unwrap();

    let mut nodes: Vec<JubJubVectorCommitmentInnerDigest<MTEdOnBls12_377>> = vec![];
    for node in proof.path_auth_path.iter() {
        let buf: Vec<u8> = bs58::decode(node.clone()).into_vec().unwrap();
        let node = JubJubVectorCommitmentInnerDigest::<MTEdOnBls12_377>::deserialize_compressed(buf.as_slice()).unwrap();

        nodes.push(node);
    }

    let buf: Vec<u8> = bs58::decode(proof.record.clone()).into_vec().unwrap();
    let record = G1Affine::deserialize_compressed(buf.as_slice()).unwrap();

    let buf: Vec<u8> = bs58::decode(proof.root.clone()).into_vec().unwrap();
    let root = JubJubVectorCommitment::<MTEdOnBls12_377>::deserialize_compressed(buf.as_slice()).unwrap();

    JubJubVectorCommitmentOpeningProof {
        path: JubJubVectorCommitmentPath {
            leaf_sibling_hash: leaf_digest,
            auth_path: nodes,
            leaf_index: proof.path_leaf_index,
        },
        record,
        root,
    }
}


#[allow(non_camel_case_types)]
pub enum PaymentGrothPublicInput {
    ROOT_X = 0, // merkle root for proving membership of input utxo
    ROOT_Y = 1, // merkle root for proving membership of input utxo
    NULLIFIER = 2, // nullifier to the input utxo
    COMMITMENT_X = 3, // commitment of the output utxo
    COMMITMENT_Y = 4, // commitment of the output utxo
}

#[allow(non_camel_case_types)]
pub enum OnrampGrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COMMITMENT_X = 2,
    COMMITMENT_Y = 3,
}

#[allow(non_camel_case_types)]
pub enum MerkleUpdateGrothPublicInput {
    LEAF_INDEX = 0, // index (starting at 0) of the leaf node being inserted
    LEAF_VALUE_X = 1, // leaf being inserted
    LEAF_VALUE_Y = 2, // leaf being inserted
    OLD_ROOT_X = 3, // merkle tree root before the update
    OLD_ROOT_Y = 4, // merkle tree root before the update
    NEW_ROOT_X = 5, // merkle tree root after the update
    NEW_ROOT_Y = 6, // merkle tree root after the update
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldElementBs58 {
	pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinBs58 {
	pub fields: [String; NUM_FIELDS],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrothProofBs58 {
    pub proof: String,
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnRampProofBs58 {
    pub on_ramp_proof: GrothProofBs58,
    pub merkle_update_proof: GrothProofBs58
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProofBs58 {
    pub payment_proof: GrothProofBs58,
    pub merkle_update_proof: GrothProofBs58
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkProofBs58 {
    // commitments to input coins data structures
    pub input_coins_com: Vec<String>,
    // commitments to output coins data structures
    pub output_coins_com: Vec<String>,
    // commitment to quotient polynomial
    pub quotient_com: String,
    // commitments to additional polynomials
    pub additional_com: Vec<String>,

    // openings of input coin polyomials at r
    pub input_coins_opening: Vec<String>,
    // openings of output coin polyomials at r
    pub output_coins_opening: Vec<String>,
    // opening of quotient polynomial at r
    pub quotient_opening: String,
    // openings of additional polynomials at r
    pub additional_opening: Vec<String>,

    pub input_coins_opening_proof: Vec<String>,
    pub output_coins_opening_proof: Vec<String>,
    pub quotient_opening_proof: String,
    pub additional_opening_proof: Vec<String>,
}


pub fn field_element_to_bs58(field: &F) -> FieldElementBs58 {
    FieldElementBs58 { field: encode_f_as_bs58_str(field) }
}

pub fn field_element_from_bs58(fieldbs58: &FieldElementBs58) -> F {
    decode_bs58_str_as_f(&fieldbs58.field)
}

pub fn coin_to_bs58(coin: &Coin<F>) -> CoinBs58 {
    CoinBs58 { fields: 
        coin
        .iter()
        .map(|f| encode_f_as_bs58_str(f))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }
}

pub fn coin_from_bs58(coin: &CoinBs58) -> Coin<F> {
	coin.fields
		.iter()
		.map(|s| decode_bs58_str_as_f(s))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

pub fn plonk_proof_from_bs58(proof: &PlonkProofBs58) -> PlonkProof {
    let input_coins_com = proof.input_coins_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let output_coins_com = proof.output_coins_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let quotient_com = decode_bs58_str_as_g1(&proof.quotient_com);

    let additional_com = proof.additional_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let input_coins_opening = proof.input_coins_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let output_coins_opening = proof.output_coins_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let quotient_opening = decode_bs58_str_as_f(&proof.quotient_opening);

    let additional_opening = proof.additional_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let input_coins_opening_proof = proof.input_coins_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let output_coins_opening_proof = proof.output_coins_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let quotient_opening_proof = decode_bs58_str_as_g1(&proof.quotient_opening_proof);

    let additional_opening_proof = proof.additional_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    PlonkProof {
        input_coins_com,
        output_coins_com,
        quotient_com,
        additional_com,

        input_coins_opening,
        output_coins_opening,
        quotient_opening,
        additional_opening,

        input_coins_opening_proof,
        output_coins_opening_proof,
        quotient_opening_proof,
        additional_opening_proof,
    }
}

pub fn plonk_proof_to_bs58(proof: &PlonkProof) -> PlonkProofBs58 {
    let input_coins_com = proof.input_coins_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_com = proof.output_coins_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_com = encode_g1_as_bs58_str(&proof.quotient_com);

    let additional_com = proof.additional_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let input_coins_opening = proof.input_coins_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_opening = proof.output_coins_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_opening = encode_f_as_bs58_str(&proof.quotient_opening);

    let additional_opening = proof.additional_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let input_coins_opening_proof = proof.input_coins_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_opening_proof = proof.output_coins_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_opening_proof = encode_g1_as_bs58_str(&proof.quotient_opening_proof);

    let additional_opening_proof = proof.additional_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    PlonkProofBs58 {
        input_coins_com,
        output_coins_com,
        quotient_com,
        additional_com,

        input_coins_opening,
        output_coins_opening,
        quotient_opening,
        additional_opening,

        input_coins_opening_proof,
        output_coins_opening_proof,
        quotient_opening_proof,
        additional_opening_proof,
    }
}

pub fn groth_proof_to_bs58(
    proof: &Proof<ConstraintPairing>,
    public_inputs: &Vec<ConstraintF>
) -> GrothProofBs58 {
    let public_inputs = public_inputs
        .iter()
        .map(|f| encode_constraintf_as_bs58_str(f))
        .collect::<Vec<String>>();

    let mut buffer: Vec<u8> = Vec::new();
    proof.serialize_compressed(&mut buffer).unwrap();
    let proof = bs58::encode(buffer).into_string();

    GrothProofBs58 {
        proof,
        public_inputs,
    }
}

pub fn groth_proof_from_bs58(proof: &GrothProofBs58) -> 
    (Proof<ConstraintPairing>, Vec<ConstraintF>) {
    let public_inputs = proof.public_inputs
        .iter()
        .map(|s| decode_bs58_str_as_constraintf(s))
        .collect::<Vec<ConstraintF>>();

    let buf: Vec<u8> = bs58::decode(proof.proof.clone()).into_vec().unwrap();
    let proof = Proof::<BW6_761>::deserialize_compressed(buf.as_slice()).unwrap();

    (proof, public_inputs)
}

fn decode_bs58_str_as_constraintf(msg: &String) -> ConstraintF {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    ConstraintF::deserialize_compressed(buf.as_slice()).unwrap()
}

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

fn decode_bs58_str_as_g1(msg: &String) -> G1Affine {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G1Affine::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}

fn encode_constraintf_as_bs58_str(value: &ConstraintF) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

fn encode_g1_as_bs58_str(value: &G1Affine) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

