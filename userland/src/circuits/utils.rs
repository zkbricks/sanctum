use std::fs::*;
use std::io::Read;

use ark_serialize::*;
use ark_groth16::*;
use ark_bw6_761::{*};

use lib_mpc_zexe::vector_commitment::bytes::sha256::{
    JZVectorCommitment as Sha2VectorCommitment,
    JZVectorCommitmentOpeningProof as Sha2VectorCommitmentOpeningProof,
    JZVectorCommitmentPath as Sha2VectorCommitmentPath,
    JZVectorCommitmentLeafDigest as Sha2VectorCommitmentLeafDigest,
    JZVectorCommitmentInnerDigest as Sha2VectorCommitmentInnerDigest
};
use lib_mpc_zexe::protocol::*;

pub fn write_groth_key_to_file(
    pk: &ProvingKey<BW6_761>,
    pk_file_path: &str,
    vk: &VerifyingKey<BW6_761>,
    vk_file_path: &str
) {
    let mut serialized_pk = Vec::new();
    pk.serialize_uncompressed(&mut serialized_pk).unwrap();

    let mut serialized_vk = Vec::new();
    vk.serialize_uncompressed(&mut serialized_vk).unwrap();

    let mut file = File::create(pk_file_path).unwrap();
    file.write_all(&serialized_pk).unwrap();
    println!("wrote {} bytes to {}", serialized_pk.len(), pk_file_path);

    let mut file = File::create(vk_file_path).unwrap();
    file.write_all(&serialized_vk).unwrap();
    println!("wrote {} bytes to {}", serialized_vk.len(), vk_file_path);

}

pub fn read_groth_proving_key_from_file(
    pk_file_path: &str
) -> ProvingKey<BW6_761> {

    let pk = ProvingKey::<BW6_761>::deserialize_uncompressed(
        get_file_as_byte_vec(&pk_file_path).as_slice()
    ).unwrap();
    println!("read pk from {}", pk_file_path);

    pk
}

pub fn read_groth_verification_key_from_file(
    vk_file_path: &str
) -> VerifyingKey<BW6_761> {

    let vk = VerifyingKey::<BW6_761>::deserialize_uncompressed(
        get_file_as_byte_vec(&vk_file_path).as_slice()
    ).unwrap();
    println!("read vk from {}", vk_file_path);

    vk
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    println!("read bytes from {}", filename);

    buffer
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
    println!("[sha2_vector_commitment_opening_proof_to_bs58] record: {:?}", record);

    let mut buffer: Vec<u8> = Vec::new();
    proof.root.serialize_compressed(&mut buffer).unwrap();
    let root = bs58::encode(buffer).into_string();
    println!("[sha2_vector_commitment_opening_proof_to_bs58] root: {:?}", root);

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