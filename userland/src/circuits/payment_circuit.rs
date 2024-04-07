use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;
use std::cmp::min;

use ark_ec::*;
use ark_ff::*;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use lib_mpc_zexe::vector_commitment;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::{*, constraints::*};
use lib_mpc_zexe::record_commitment::kzg::{*, constraints::*};
use lib_mpc_zexe::prf::{*, constraints::*};

use super::{AMOUNT, ASSET_ID, RHO, OWNER};
use super::utils;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types, unused)]
pub enum GrothPublicInput {
    ROOT_X = 0, // merkle root for proving membership of input utxo
    ROOT_Y = 1, // merkle root for proving membership of input utxo
    NULLIFIER = 2, // nullifier to the input utxo
    COMMITMENT_X = 3, // commitment of the output utxo
    COMMITMENT_Y = 4, // commitment of the output utxo
}


/// OnRampCircuit is used to prove that the new coin being created
/// during the on-ramp process commits to the amount and asset_id
/// being claimed by the client.
pub struct PaymentCircuit {
    /// public parameters (CRS) for the KZG commitment scheme
    pub crs: JZKZGCommitmentParams<5>,

    /// public parameters for the PRF evaluation
    pub prf_params: JZPRFParams,

     /// public parameters for the vector commitment scheme
     pub vc_params: JZVectorCommitmentParams,

    /// all fields of the input utxo, for the asset owned by the sender
    pub input_utxo: JZRecord<5>,

    // all fields of the output utxo listing recepient as the owner
    pub output_utxo: JZRecord<5>,

    /// secret key for proving ownership of the spent coin
    pub sk: [u8; 32],

    /// Merkle opening proof for proving existence of the unspent coin
    pub unspent_coin_existence_proof: JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>,
}

/// ConstraintSynthesizer is a trait that is implemented for the OnRampCircuit;
/// it contains the logic for generating the constraints for the SNARK circuit
/// that will be used to generate the local proof encoding a valid coin creation.
impl ConstraintSynthesizer<ConstraintF> for PaymentCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        let crs_var = JZKZGCommitmentParamsVar::<5>::new_constant(
            cs.clone(),
            self.crs
        ).unwrap();

        // PRF makes use of public parameters, so we make them constant
        let prf_params_var = JZPRFParamsVar::new_constant(
            cs.clone(),
            &self.prf_params
        ).unwrap();

        let merkle_params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &self.vc_params
        ).unwrap();

        //--------------- knowledge of opening of input UTXO commitment ------------------

        let input_utxo_record = self.input_utxo.borrow();

        let input_utxo_var = JZRecordVar::<5>::new_witness(
            cs.clone(),
            || Ok(input_utxo_record)
        ).unwrap();

        //trigger constraint generation to compute the SHA256 commitment
        lib_mpc_zexe::record_commitment::kzg::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &input_utxo_var
        ).unwrap();

        //--------------- knowledge of opening of output UTXO commitment ------------------
        
        let output_utxo_record = self.output_utxo.borrow();
        let output_utxo_commitment = output_utxo_record.commitment().into_affine();

        let output_utxo_var = JZRecordVar::<5>::new_witness(
            cs.clone(),
            || Ok(output_utxo_record)
        ).unwrap();

        // trigger constraint generation to compute the SHA256 commitment
        lib_mpc_zexe::record_commitment::kzg::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &output_utxo_var
        ).unwrap();

        // -------------------- Nullifier -----------------------
        // we now prove that the nullifier within the statement is computed correctly

        // prf_instance nullifier is responsible for proving that the computed
        // nullifier encoded in the L1-destined proof is correct; 
        // we use the same idea as zCash here, where nullifier = PRF(rho; sk)
        let prf_instance_nullifier = JZPRFInstance::new(
            &self.prf_params, self.input_utxo.fields[RHO].as_slice(), &self.sk
        );
        let nullifier = prf_instance_nullifier.evaluate();

        let nullifier_prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(prf_instance_nullifier)
        ).unwrap();

        // trigger the constraint generation for the PRF instance
        lib_mpc_zexe::prf::constraints::generate_constraints(
            cs.clone(),
            &prf_params_var,
            &nullifier_prf_instance_var
        );

        //--------------- Private key knowledge ------------------
        // we will prove that the coin is owned by the spender;
        // we just invoke the constraint generation for the PRF instance

        // prf_instance_ownership is responsible for proving knowledge
        // of the secret key corresponding to the coin's public key;
        // we use the same idea as zCash here, where pk = PRF(0; sk)
        let ownership_prf_instance = JZPRFInstance::new(
            &self.prf_params, &[0u8; 32], &self.sk
        );

        // PRF arguments for the secret witness
        let ownership_prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(ownership_prf_instance)
        ).unwrap();

        // trigger the constraint generation for the PRF instance
        lib_mpc_zexe::prf::constraints::generate_constraints(
            cs.clone(),
            &prf_params_var,
            &ownership_prf_instance_var
        );


        //--------------- Merkle tree proof ------------------
        // Here, we will prove that the commitment to the spent coin
        // exists in the merkle tree of all created coins

        let proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&self.unspent_coin_existence_proof)
        ).unwrap();

        // //generate the merkle proof verification circuitry
        vector_commitment::bytes::pedersen::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &proof_var
        );


        //--------------- Declare all the input variables ------------------

        let root_x_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_x"), 
            || { Ok(self.unspent_coin_existence_proof.root.x) },
        ).unwrap();

        let root_y_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_y"), 
            || { Ok(self.unspent_coin_existence_proof.root.y) },
        ).unwrap();

        // allocate the nullifier as an input variable in the statement
        let nullifier_inputvar = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "nullifier"), 
            || Ok(utils::bytes_to_field::<ConstraintF, 6>(&nullifier)),
        ).unwrap();


        let output_utxo_commitment_x_input_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "output_commitment_x"), 
            || { Ok(output_utxo_commitment.x) },
        ).unwrap();

        let output_utxo_commitment_y_input_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "output_commitment_y"), 
            || { Ok(output_utxo_commitment.y) },
        ).unwrap();


        //--------------- Binding all circuit gadgets together ------------------

        // 1. do both PRFs use the same secret key?
        for (i, byte_var) in ownership_prf_instance_var.key_var.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.key_var[i])?;
        }

        // 2. does the nullifier PRF use rho as input?
        for (i, byte_var) in nullifier_prf_instance_var.input_var.iter().enumerate() {
            byte_var.enforce_equal(&input_utxo_var.fields[RHO][i])?;
        }

        // 3. prove ownership of the coin. Does sk correspond to coin's pk?
        for (i, byte_var) in input_utxo_var.fields[OWNER].iter().enumerate() {
            byte_var.enforce_equal(&ownership_prf_instance_var.output_var[i])?;
        }

        // 4. constrain the nullifier in the statement to equal the PRF output
        let nullifier_prf_byte_vars: Vec::<UInt8<ConstraintF>> = nullifier_inputvar
            .to_bytes()?
            .to_vec();
        for (i, byte_var) in nullifier_prf_instance_var.output_var.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_byte_vars[i])?;
        }

        // 5. constrain the output utxo commitment in the statement to equal the computed commitment output
        let output_utxo_commitment_x_byte_vars: Vec::<UInt8<ConstraintF>> = output_utxo_commitment_x_input_var
            .to_bytes()?
            .to_vec();
        for (i, byte_var) in output_utxo_var.commitment.to_affine()?.x.to_bytes()?.iter().enumerate() {
            byte_var.enforce_equal(&output_utxo_commitment_x_byte_vars[i])?;
        }

        let output_utxo_commitment_y_byte_vars: Vec::<UInt8<ConstraintF>> = output_utxo_commitment_y_input_var
            .to_bytes()?
            .to_vec();
        for (i, byte_var) in output_utxo_var.commitment.to_affine()?.y.to_bytes()?.iter().enumerate() {
            byte_var.enforce_equal(&output_utxo_commitment_y_byte_vars[i])?;
        }

        // 6. does the leaf node in the merkle proof equal the input utxo commitment?
        let input_utxo_commitment_byte_vars: Vec::<UInt8<ConstraintF>> = input_utxo_var
            .commitment // grab the commitment variable
            .to_affine()? // convert it to an affine point
            .x // grab the x-coordinate
            .to_bytes()?; // let's use arkworks' to_bytes gadget
        let proof_var_leaf_var_bytes: Vec::<UInt8<ConstraintF>> = proof_var.leaf_var
            .iter()
            .cloned()
            .collect();
        for i in 0..min(input_utxo_commitment_byte_vars.len(), proof_var_leaf_var_bytes.len()) {
            input_utxo_commitment_byte_vars[i].enforce_equal(&proof_var_leaf_var_bytes[i])?;
        }

        // 7. does the proof use the same root as what is declared in the statement?
        proof_var.root_var.x.enforce_equal(&root_x_inputvar)?;
        proof_var.root_var.y.enforce_equal(&root_y_inputvar)?;

        // 8. conservation of asset value
        for field in [AMOUNT, ASSET_ID] {
            input_utxo_var
            .fields[field]
            .iter()
            .zip(output_utxo_var.fields[field].iter())
            .for_each(|(input_byte, output_byte)| {
                input_byte.enforce_equal(output_byte).unwrap();
            });
        }

        Ok(())
    }
}


pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    let (prf_params, vc_params, crs) = utils::trusted_setup();

    // create a circuit with a dummy witness
    let circuit = {
    
        // let's create the universe of dummy utxos
        let mut records = Vec::new();
        for _ in 0..(1 << MERKLE_TREE_LEVELS) {
            records.push(utils::get_dummy_utxo(&crs).commitment().into_affine());
        }
    
        // let's create a database of coins, and generate a merkle proof
        // we need this in order to create a circuit with appropriate public inputs
        let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records[..]);
        let merkle_proof = JZVectorCommitmentOpeningProof {
            root: db.commitment(),
            record: db.get_record(0).clone(),
            path: db.proof(0),
        };

        // note that circuit setup does not care about the values of witness variables
        PaymentCircuit {
            crs: crs.clone(),
            prf_params: prf_params,
            vc_params: vc_params,
            sk: [0u8; 32],
            input_utxo: utils::get_dummy_utxo(&crs), // doesn't matter what value the coin has
            output_utxo: utils::get_dummy_utxo(&crs), // again, doesn't matter what value
            unspent_coin_existence_proof: merkle_proof,
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
    input_utxo: &JZRecord<5>,
    output_utxo: &JZRecord<5>,
    unspent_coin_existence_proof: &JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>,
    sk: &[u8; 32]
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let (prf_params, vc_params, crs) = utils::trusted_setup();

    let nullifier = utils::bytes_to_field::<ConstraintF, 6>(
        &JZPRFInstance::new(&prf_params, input_utxo.fields[RHO].as_slice(), sk).evaluate()
    );

    let circuit = PaymentCircuit {
        crs: crs,
        prf_params: prf_params,
        vc_params: vc_params,
        sk: *sk,
        input_utxo: input_utxo.clone(),
        output_utxo: output_utxo.clone(),
        unspent_coin_existence_proof: unspent_coin_existence_proof.clone(),
    };
    
    // arrange the public inputs based on the GrothPublicInput enum definition
    // pub enum GrothPublicInput {
    //     ROOT_X = 0, // merkle root for proving membership of input utxo
    //     ROOT_Y = 1, // merkle root for proving membership of input utxo
    //     NULLIFIER = 2, // nullifier to the input utxo
    //     COMMITMENT_X = 3, // commitment of the output utxo
    //     COMMITMENT_Y = 4, // commitment of the output utxo
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        unspent_coin_existence_proof.root.x,
        unspent_coin_existence_proof.root.y,
        nullifier,
        output_utxo.commitment().into_affine().x,
        output_utxo.commitment().into_affine().y
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
