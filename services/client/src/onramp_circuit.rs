use std::cmp::min;
use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;

use ark_ff::*;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use lib_mpc_zexe::record_commitment::sha256::{*, constraints::*};
use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::utils;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types, unused)]
pub enum GrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COMMITMENT = 2,
}


/// OnRampCircuit is used to prove that the new coin being created
/// during the on-ramp process commits to the amount and asset_id
/// being claimed by the client.
pub struct OnRampCircuit {
    /// all fields of the utxo is a secret witness in the proof generation
    pub unspent_utxo: JZRecord<8>,
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

        //----------------- declaration of public values for the coin ---------------------

        // we need the asset_id and amount to be public inputs to the circuit
        // so let's create variables for them
        let asset_id = utils::bytes_to_field::<ConstraintF, 6>(
            &self.unspent_utxo.fields[ASSET_ID]
        );

        let asset_id_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "asset_id"), 
            || { Ok(asset_id) },
        ).unwrap();

        let amount = utils::bytes_to_field::<ConstraintF, 6>(
            &self.unspent_utxo.fields[AMOUNT]
        );

        let amount_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "amount"), 
            || { Ok(amount) },
        ).unwrap();

        //--------------- knowledge of opening of unspent UTXO commitment ------------------
        
        let unspent_utxo_record = self.unspent_utxo.borrow();

        let unspent_utxo_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(unspent_utxo_record)
        ).unwrap();

        let unspent_utxo_commitment = utils::bytes_to_field::<ark_bls12_377::Fq, 6>(
            &unspent_utxo_record.commitment()
        );

        // a commitment is an (affine) group element so we separately 
        // expose the x and y coordinates, computed below
        let unspent_utxo_commitment_input_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "commitment"), 
            || { Ok(unspent_utxo_commitment) },
        ).unwrap();

        // fire off the constraint generation which will include the 
        // circuitry to compute the KZG commitment
        lib_mpc_zexe::record_commitment::sha256::constraints::generate_constraints(
            cs.clone(),
            &unspent_utxo_var
        ).unwrap();

        //--------------- Binding all circuit gadgets together ------------------

        // NOTE: we are assuming to_bytes uses little-endian encoding, which I believe it does

        // let's constrain the input variable to be the digest that we computed
        let unspent_utxo_commitment_input_var_bytes = unspent_utxo_commitment_input_var.to_bytes().unwrap();
        let unspent_utxo_commitment_computed_var_bytes = unspent_utxo_var.commitment.to_bytes().unwrap();
        for i in 0..min(
            unspent_utxo_commitment_input_var_bytes.len(),
            unspent_utxo_commitment_computed_var_bytes.len()
        ) {
            unspent_utxo_commitment_input_var_bytes[i].enforce_equal(&unspent_utxo_commitment_computed_var_bytes[i])?;
        }

        // let's constrain the amount bits to be equal to the amount_var
        let amount_inputvar_bytes = amount_var.to_bytes()?;
        for i in 0..min(unspent_utxo_var.fields[AMOUNT].len(), amount_inputvar_bytes.len()) {
            unspent_utxo_var.fields[AMOUNT][i].enforce_equal(&amount_inputvar_bytes[i])?;
        }

        // let's constrain the asset_id bits to be equal to the asset_id_var
        let assetid_inputvar_bytes = asset_id_var.to_bytes()?;
        for i in 0..min(unspent_utxo_var.fields[ASSET_ID].len(), assetid_inputvar_bytes.len()) {
            unspent_utxo_var.fields[ASSET_ID][i].enforce_equal(&assetid_inputvar_bytes[i])?;
        }

        Ok(())
    }
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    // create a circuit with a dummy witness
    let circuit = {
        
        // our dummy witness is a coin with all fields set to zero
        let fields: [Vec<u8>; 8] = 
        [
            vec![0u8; 31], //entropy
            vec![0u8; 31], //owner
            vec![0u8; 31], //asset id
            vec![0u8; 31], //amount
            vec![AppId::OWNED as u8], //app id
            vec![0u8; 31],
            vec![0u8; 31],
            vec![0u8; 31],
        ];

        // let's create our dummy coin out of the above zeroed fields
        let coin = JZRecord::<8>::new(&fields, &[0u8; 31].into());
    
        OnRampCircuit { unspent_utxo: coin.clone() }
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
    unspent_coin: &JZRecord<8>,
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let circuit = OnRampCircuit { unspent_utxo: unspent_coin.clone() };

    // native computation of the created coin's commitment
    let unspent_coin_com = utils::bytes_to_field::<ConstraintF, 6>(
        circuit.unspent_utxo.commitment().as_slice()
    );

    // construct a BW6_761 field element from the asset_id bits
    let asset_id = utils::bytes_to_field::<ConstraintF, 6>(
        &circuit.unspent_utxo.fields[ASSET_ID]
    );

    // construct a BW6_761 field element from the amount bits
    let amount = utils::bytes_to_field::<ConstraintF, 6>(
        &circuit.unspent_utxo.fields[AMOUNT]
    );

    // arrange the public inputs based on the GrothPublicInput enum definition
    // pub enum GrothPublicInput {
    //     ASSET_ID = 0,
    //     AMOUNT = 1,
    //     COMMITMENT = 2,
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        asset_id,
        amount,
        unspent_coin_com
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
