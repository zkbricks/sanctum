use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;
use std::cmp::min;

use ark_ff::*;
use ark_ec::CurveGroup;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::{ConstraintSynthesizer, *};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use ark_crypto_primitives::to_uncompressed_bytes;

use lib_mpc_zexe::vector_commitment;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::{
    *, constraints::*, constraints::JZVectorCommitmentParamsVar,
    config::ed_on_bw6_761::MerkleTreeParams as MTParams,
    config::ed_on_bw6_761::MerkleTreeParamsVar as MTParamsVar,
};
use lib_mpc_zexe::merkle_tree::constraints::PathVar;

use super::utils;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types)]
pub enum GrothPublicInput {
    LEAF_INDEX = 0, // index (starting at 0) of the leaf node being inserted
    LEAF_VALUE_X = 1, // leaf being inserted
    LEAF_VALUE_Y = 2, // leaf being inserted
    OLD_ROOT_X = 3, // merkle tree root before the update
    OLD_ROOT_Y = 4, // merkle tree root before the update
    NEW_ROOT_X = 5, // merkle tree root after the update
    NEW_ROOT_Y = 6, // merkle tree root after the update
}


/// MerkleUpdateCircuit proves that the Merkle tree is updated correctly
pub struct MerkleUpdateCircuit {
    /// public parameters for the vector commitment scheme
    pub vc_params: JZVectorCommitmentParams<MTParams>,

    pub leaf_index: usize,

    /// Merkle proof for leaf index
    pub old_merkle_proof: JZVectorCommitmentOpeningProof<MTParams, ark_bls12_377::G1Affine>,

    /// Merkle proof for leaf index
    pub new_merkle_proof: JZVectorCommitmentOpeningProof<MTParams, ark_bls12_377::G1Affine>,
}

fn enforce_path_equality(
    _cs: ConstraintSystemRef<ConstraintF>,
    path1: &PathVar<MTParams, ConstraintF, MTParamsVar>,
    path2: &PathVar<MTParams, ConstraintF, MTParamsVar>
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
        vector_commitment::bytes::pedersen::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &old_proof_var
        );

        // //generate the merkle proof verification circuitry
        vector_commitment::bytes::pedersen::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &new_proof_var
        );

        //--------------- Declare all the input variables ------------------

        let _leaf_index_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "leaf_index"), 
            || { Ok(utils::bytes_to_field::<ConstraintF, 6>(&to_uncompressed_bytes!(self.leaf_index).unwrap())) },
        ).unwrap();

        let leaf_value_x_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "leaf_value_x"), 
            || { Ok(self.new_merkle_proof.record.x) },
        ).unwrap();

        let _leaf_value_y_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "leaf_value_y"), 
            || { Ok(self.new_merkle_proof.record.y) },
        ).unwrap();

        let old_root_x_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "old_root_x"), 
            || { Ok(self.old_merkle_proof.root.x) },
        ).unwrap();

        let old_root_y_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "old_root_y"), 
            || { Ok(self.old_merkle_proof.root.y) },
        ).unwrap();

        let new_root_x_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "new_root_x"), 
            || { Ok(self.new_merkle_proof.root.x) },
        ).unwrap();

        let new_root_y_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs.clone(), "new_root_y"), 
            || { Ok(self.new_merkle_proof.root.y) },
        ).unwrap();

        //--------------- Binding all circuit gadgets together ------------------

        enforce_path_equality(cs, &old_proof_var.path_var, &new_proof_var.path_var)?;

        enforce_fqvar_equality(old_root_x_inputvar, old_proof_var.root_var.x)?;
        enforce_fqvar_equality(old_root_y_inputvar, old_proof_var.root_var.y)?;
        enforce_fqvar_equality(new_root_x_inputvar, new_proof_var.root_var.x)?;
        enforce_fqvar_equality(new_root_y_inputvar, new_proof_var.root_var.y)?;

        let leaf_value_x_byte_vars = leaf_value_x_inputvar.to_bytes()?;
        // constrain equality w.r.t. to the leaf node, byte by byte
        for (i, byte_var) in leaf_value_x_byte_vars.iter().enumerate() {
            // the serialization impl for CanonicalSerialize does x first
            byte_var.enforce_equal(&new_proof_var.leaf_var[i])?;
        }

        Ok(())
    }
}


fn enforce_fqvar_equality(
    e1: ark_bls12_377::constraints::FqVar,
    e2: ark_bls12_377::constraints::FqVar
) -> Result<()> {
    let e1_bytes: Vec<UInt8<ConstraintF>> = e1.to_bytes()?;
    let e2_bytes: Vec<UInt8<ConstraintF>> = e2.to_bytes()?;

    for i in 0..min(e1_bytes.len(), e2_bytes.len()) {
        e1_bytes[i].enforce_equal(&e2_bytes[i])?;
    }

    Ok(())
}


pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    let (_, vc_params, crs) = utils::trusted_setup();

    // create a circuit with a dummy witness
    let circuit = {
    
        // let's create the universe of dummy utxos
        let mut records = Vec::new();
        for _ in 0..(1 << MERKLE_TREE_LEVELS) {
            records.push(utils::get_dummy_utxo(&crs).commitment().into_affine());
        }
    
        let leaf_index = 0 as usize;
        // let's create a database of coins, and generate a merkle proof
        // we need this in order to create a circuit with appropriate public inputs
        let db = JZVectorDB::<MTParams, ark_bls12_377::G1Affine>::new(vc_params, &records);
        let merkle_proof = JZVectorCommitmentOpeningProof {
            root: db.commitment(),
            record: db.get_record(leaf_index).clone(),
            path: db.proof(leaf_index),
        };

        let (_, vc_params, _) = utils::trusted_setup();
        // note that circuit setup does not care about the values of witness variables
        MerkleUpdateCircuit {
            vc_params: vc_params,
            old_merkle_proof: merkle_proof.clone(),
            new_merkle_proof: merkle_proof.clone(),
            leaf_index: leaf_index,
        }
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
    old_merkle_proof: &JZVectorCommitmentOpeningProof<MTParams, ark_bls12_377::G1Affine>,
    new_merkle_proof: &JZVectorCommitmentOpeningProof<MTParams, ark_bls12_377::G1Affine>,
    leaf_index: usize,
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let (_, vc_params, _) = utils::trusted_setup();

    let circuit = MerkleUpdateCircuit {
        vc_params: vc_params,
        leaf_index: leaf_index,
        old_merkle_proof: old_merkle_proof.clone(),
        new_merkle_proof: new_merkle_proof.clone(),
    };

    // pub enum GrothPublicInput {
    //     LEAF_INDEX = 0, // index (starting at 0) of the leaf node being inserted
    //     LEAF_VALUE_X = 1, // leaf being inserted
    //     LEAF_VALUE_Y = 2, // leaf being inserted
    //     OLD_ROOT_X = 3, // merkle tree root before the update
    //     OLD_ROOT_Y = 4, // merkle tree root before the update
    //     NEW_ROOT_X = 5, // merkle tree root after the update
    //     NEW_ROOT_Y = 6, // merkle tree root after the update
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        utils::bytes_to_field::<ConstraintF, 6>(&to_uncompressed_bytes!(leaf_index).unwrap()), //LEAF_INDEX
        new_merkle_proof.record.x, //LEAF_VALUE_X
        new_merkle_proof.record.y, //LEAF_VALUE_Y
        old_merkle_proof.root.x, //OLD_ROOT_X
        old_merkle_proof.root.y, //OLD_ROOT_Y
        new_merkle_proof.root.x, //NEW_ROOT_X
        new_merkle_proof.root.y, //NEW_ROOT_Y
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let now = std::time::Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    println!("merkle update proof generated in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );
    
    (proof, public_inputs)
}
