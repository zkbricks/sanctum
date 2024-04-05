
use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;
use std::cmp::min;

use ark_ff::*;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::{ConstraintSynthesizer, *};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use ark_crypto_primitives::to_uncompressed_bytes;

use lib_mpc_zexe::vector_commitment;
use lib_mpc_zexe::vector_commitment::bytes::sha256::{
    *, constraints::*, constraints::Sha256MerkleTreeParamsVar, common::Sha256MerkleTreeParams
};
use lib_mpc_zexe::record_commitment::sha256::*;
use lib_mpc_zexe::merkle_tree::constraints::PathVar;
use lib_mpc_zexe::utils;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types, unused)]
pub enum GrothPublicInput {
    LEAF_INDEX = 0, // index (starting at 0) of the leaf node being inserted
    LEAF_VALUE = 1, // leaf being inserted
    OLD_ROOT = 2, // merkle tree root before the update
    NEW_ROOT = 3, // merkle tree root after the update
}


/// MerkleUpdateCircuit proves that the Merkle tree is updated correctly
pub struct MerkleUpdateCircuit {
    /// public parameters for the vector commitment scheme
    pub vc_params: JZVectorCommitmentParams,

    pub leaf_index: usize,

    /// Merkle proof for leaf index
    pub old_merkle_proof: JZVectorCommitmentOpeningProof<Vec<u8>>,

    /// Merkle proof for leaf index
    pub new_merkle_proof: JZVectorCommitmentOpeningProof<Vec<u8>>,
}

fn enforce_path_equality(
    _cs: ConstraintSystemRef<ConstraintF>,
    path1: &PathVar<Sha256MerkleTreeParams, ConstraintF, Sha256MerkleTreeParamsVar>,
    path2: &PathVar<Sha256MerkleTreeParams, ConstraintF, Sha256MerkleTreeParamsVar>
) -> Result<()> {
        path1.path.enforce_equal(&path2.path)?;
        path1.auth_path.enforce_equal(&path2.auth_path)?;
        path1.leaf_sibling.enforce_equal(&path2.leaf_sibling)?;
        path1.leaf_is_right_child.enforce_equal(&path2.leaf_is_right_child)?;
    Ok(())
}

/// ConstraintSynthesizer is a trait that is implemented for the OnRampCircuit;
/// it contains the logic for generating the constraints for the SNARK circuit
/// that will be used to generate the local proof encoding a valid coin creation.
impl ConstraintSynthesizer<ConstraintF> for MerkleUpdateCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        let merkle_params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &self.vc_params
        ).unwrap();


        //--------------- Merkle tree proof ------------------

        let old_proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&self.old_merkle_proof)
        ).unwrap();

        let new_proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&self.new_merkle_proof)
        ).unwrap();

        // //generate the merkle proof verification circuitry
        vector_commitment::bytes::sha256::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &old_proof_var
        );

        // //generate the merkle proof verification circuitry
        vector_commitment::bytes::sha256::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &new_proof_var
        );

        //--------------- Declare all the input variables ------------------

        let _leaf_index_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "leaf_index"), 
            || { Ok(utils::bytes_to_field::<ConstraintF, 6>(&to_uncompressed_bytes!(self.leaf_index).unwrap())) },
        ).unwrap();

        let _leaf_value_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "leaf_value"), 
            || { Ok(utils::bytes_to_field::<ConstraintF, 6>(&self.new_merkle_proof.record)) },
        ).unwrap();

        let old_root_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "old_root"), 
            || { Ok(utils::bytes_to_field::<ConstraintF, 6>(&self.old_merkle_proof.root)) },
        ).unwrap();

        let new_root_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "new_root"), 
            || { Ok(utils::bytes_to_field::<ConstraintF, 6>(&self.new_merkle_proof.root)) },
        ).unwrap();

        //--------------- Binding all circuit gadgets together ------------------

        enforce_path_equality(cs, &old_proof_var.path_var, &new_proof_var.path_var)?;

        let root_var_bytes = old_root_inputvar.to_bytes()?;
        let proof_var_root_var_bytes = old_proof_var.root_var.to_bytes()?;
        for i in 0..min(root_var_bytes.len(), proof_var_root_var_bytes.len()) {
            root_var_bytes[i].enforce_equal(&proof_var_root_var_bytes[i])?;
        }

        let root_var_bytes = new_root_inputvar.to_bytes()?;
        let proof_var_root_var_bytes = new_proof_var.root_var.to_bytes()?;
        for i in 0..min(root_var_bytes.len(), proof_var_root_var_bytes.len()) {
            root_var_bytes[i].enforce_equal(&proof_var_root_var_bytes[i])?;
        }

        Ok(())
    }
}

fn get_dummy_utxo() -> JZRecord<5> {
    let fields: [Vec<u8>; 5] = 
    [
        vec![0u8; 31], //entropy
        vec![0u8; 31], //owner
        vec![0u8; 31], //asset id
        vec![0u8; 31], //amount
        vec![0u8; 31], //rho
    ];

    JZRecord::<5>::new(&fields, &[0u8; 31].into())
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // create a circuit with a dummy witness
    let circuit = {
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
    
        // let's create the universe of dummy utxos
        let mut records = Vec::new();
        for _ in 0..(1 << MERKLE_TREE_LEVELS) {
            records.push(get_dummy_utxo().commitment());
        }
    
        let leaf_index = 0 as usize;
        // let's create a database of coins, and generate a merkle proof
        // we need this in order to create a circuit with appropriate public inputs
        let db = JZVectorDB::<Vec<u8>>::new(&vc_params, &records);
        let merkle_proof = JZVectorCommitmentOpeningProof {
            root: db.commitment(),
            record: db.get_record(leaf_index).clone(),
            path: db.proof(leaf_index),
        };

        // note that circuit setup does not care about the values of witness variables
        let circuit = MerkleUpdateCircuit {
            vc_params: vc_params,
            old_merkle_proof: merkle_proof.clone(),
            new_merkle_proof: merkle_proof.clone(),
            leaf_index: leaf_index,
        };

        circuit
    };

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

pub fn generate_groth_proof(
    pk: &ProvingKey<BW6_761>,
    old_merkle_proof: &JZVectorCommitmentOpeningProof<Vec<u8>>,
    new_merkle_proof: &JZVectorCommitmentOpeningProof<Vec<u8>>,
    leaf_index: usize,
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

    let circuit = MerkleUpdateCircuit {
        vc_params: vc_params,
        leaf_index: leaf_index,
        old_merkle_proof: old_merkle_proof.clone(),
        new_merkle_proof: new_merkle_proof.clone(),
    };

    // pub enum GrothPublicInput {
    //     LEAF_INDEX = 0, // index (starting at 0) of the leaf node being inserted
    //     LEAF_VALUE = 1, // leaf being inserted
    //     OLD_ROOT = 2, // merkle tree root before the update
    //     NEW_ROOT = 3, // merkle tree root after the update
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        utils::bytes_to_field::<ConstraintF, 6>(&to_uncompressed_bytes!(leaf_index).unwrap()),
        utils::bytes_to_field::<ConstraintF, 6>(&new_merkle_proof.record),
        utils::bytes_to_field::<ConstraintF, 6>(&old_merkle_proof.root),
        utils::bytes_to_field::<ConstraintF, 6>(&new_merkle_proof.root),
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
