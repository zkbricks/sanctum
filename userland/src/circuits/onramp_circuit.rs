use std::cmp::min;
use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;

use ark_ff::*;
use ark_ec::CurveGroup;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use lib_mpc_zexe::record_commitment::kzg::{*, constraints::*};

use super::utils;
use super::{AMOUNT, ASSET_ID};

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types, unused)]
pub enum GrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COMMITMENT_X = 2,
    COMMITMENT_Y = 3,
}


/// OnRampCircuit is used to prove that the new coin being created
/// during the on-ramp process commits to the amount and asset_id
/// being claimed by the client.
pub struct OnRampCircuit {
    /// public parameters (CRS) for the KZG commitment scheme
    pub crs: JZKZGCommitmentParams<5>,
    /// all fields of the utxo is a secret witness in the proof generation
    pub utxo: JZRecord<5>,
}

/// ConstraintSynthesizer is a trait that is implemented for the OnRampCircuit;
/// it contains the logic for generating the constraints for the SNARK circuit
/// that will be used to generate the local proof encoding a valid coin creation.
impl ConstraintSynthesizer<ConstraintF> for OnRampCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        let crs_var = JZKZGCommitmentParamsVar::<5>::new_constant(
            cs.clone(),
            self.crs
        ).unwrap();

        //----------------- declaration of public values for the coin ---------------------

        // we need the asset_id and amount to be public inputs to the circuit
        // so let's create variables for them
        let asset_id = utils::bytes_to_field::<ConstraintF, 6>(
            &self.utxo.fields[ASSET_ID]
        );

        let asset_id_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "asset_id"), 
            || { Ok(asset_id) },
        ).unwrap();

        let amount = utils::bytes_to_field::<ConstraintF, 6>(
            &self.utxo.fields[AMOUNT]
        );

        let amount_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "amount"), 
            || { Ok(amount) },
        ).unwrap();

        //--------------- knowledge of opening of unspent UTXO commitment ------------------
        
        let utxo_record = self.utxo.borrow();

        let utxo_var = JZRecordVar::<5>::new_witness(
            cs.clone(),
            || Ok(utxo_record)
        ).unwrap();

        let utxo_commitment = utxo_record.commitment().into_affine();

        // a commitment is an (affine) group element so we separately 
        // expose the x and y coordinates, computed below
        let utxo_commitment_x_input_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "commitment_x"), 
            || { Ok(utxo_commitment.x) },
        ).unwrap();

        let utxo_commitment_y_input_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "commitment_y"), 
            || { Ok(utxo_commitment.y) },
        ).unwrap();

        // fire off the constraint generation which will include the 
        // circuitry to compute the KZG commitment
        lib_mpc_zexe::record_commitment::kzg::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &utxo_var
        ).unwrap();

        //--------------- Binding all circuit gadgets together ------------------

        // NOTE: we are assuming to_bytes uses little-endian encoding, which I believe it does
        let utxo_commitment_x_input_var_bytes = utxo_commitment_x_input_var.to_bytes().unwrap();
        let utxo_commitment_x_computed_var_bytes = utxo_var.commitment.to_affine().unwrap().x.to_bytes().unwrap();
        assert!(utxo_commitment_x_input_var_bytes.len() == utxo_commitment_x_computed_var_bytes.len());
        utxo_commitment_x_input_var_bytes
            .iter()
            .zip(utxo_commitment_x_computed_var_bytes.iter())
            .for_each(|(a, b)| a.enforce_equal(b).unwrap());


        let utxo_commitment_y_input_var_bytes = utxo_commitment_y_input_var.to_bytes().unwrap();
        let utxo_commitment_y_computed_var_bytes = utxo_var.commitment.to_affine().unwrap().y.to_bytes().unwrap();
        assert!(utxo_commitment_y_input_var_bytes.len() == utxo_commitment_y_computed_var_bytes.len());
        utxo_commitment_y_input_var_bytes
            .iter()
            .zip(utxo_commitment_y_computed_var_bytes.iter())
            .for_each(|(a, b)| a.enforce_equal(b).unwrap());

        // let's constrain the amount bits to be equal to the amount_var
        let amount_inputvar_bytes = amount_var.to_bytes()?;
        for i in 0..min(utxo_var.fields[AMOUNT].len(), amount_inputvar_bytes.len()) {
            utxo_var.fields[AMOUNT][i].enforce_equal(&amount_inputvar_bytes[i])?;
        }

        // let's constrain the asset_id bits to be equal to the asset_id_var
        let assetid_inputvar_bytes = asset_id_var.to_bytes()?;
        for i in 0..min(utxo_var.fields[ASSET_ID].len(), assetid_inputvar_bytes.len()) {
            utxo_var.fields[ASSET_ID][i].enforce_equal(&assetid_inputvar_bytes[i])?;
        }

        Ok(())
    }
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {
    let (_, _, crs) = utils::trusted_setup();
    // create a circuit with a dummy witness
    let circuit = OnRampCircuit { crs: crs.clone(), utxo: utils::get_dummy_utxo(&crs) };

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

pub fn generate_groth_proof(
    pk: &ProvingKey<BW6_761>,
    utxo: &JZRecord<5>,
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let (_, _, crs) = utils::trusted_setup();
    let circuit = OnRampCircuit { crs, utxo: utxo.clone() };

    // construct a BW6_761 field element from the asset_id bits
    let asset_id = utils::bytes_to_field::<ConstraintF, 6>(
        &circuit.utxo.fields[ASSET_ID]
    );

    // construct a BW6_761 field element from the amount bits
    let amount = utils::bytes_to_field::<ConstraintF, 6>(
        &circuit.utxo.fields[AMOUNT]
    );

    // arrange the public inputs based on the GrothPublicInput enum definition
    // pub enum GrothPublicInput {
    //     ASSET_ID = 0,
    //     AMOUNT = 1,
    //     COMMITMENT_X = 2,
    //     COMMITMENT_Y = 3,
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        asset_id,
        amount,
        circuit.utxo.commitment().into_affine().x,
        circuit.utxo.commitment().into_affine().y
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
