use reqwest::Client;

use ark_ff::{*};

use lib_mpc_zexe::record_commitment::kzg::*;
use lib_mpc_zexe::protocol as protocol;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::JZVectorCommitmentOpeningProof;

use lib_sanctum::{payment_circuit, onramp_circuit, utils};

async fn request_merkle_proof(index: usize)
-> reqwest::Result<JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>> {
    let client = Client::new();
    let response = client.get("http://127.0.0.1:8080/merkle")
        .json(&index)
        .send()
        .await?
        .text()
        .await?;

    Ok(protocol::jubjub_vector_commitment_opening_proof_from_bs58(
        &serde_json::from_str(&response).unwrap())
    )
}

async fn submit_onramp_transaction(item: protocol::GrothProofBs58) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/onramp")
        .json(&item)
        .send()
        .await?;

    if response.status().is_success() {
        println!("submitted onramp tx to zkBricks sequencer...");
    } else {
        println!("Failed to create item: {:?}", response.status());
    }

    Ok(())
}

async fn submit_payment_transaction(item: protocol::GrothProofBs58) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/payment")
        .json(&item)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("submitted payment tx to zkBricks sequencer...");
    } else {
        println!("Failed to create item: {:?}", response.status());
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> reqwest::Result<()> {
    let (onramp_pk, _) = utils::read_groth_key_from_file(
        "/tmp/sanctum/onramp.pk",
        "/tmp/sanctum/onramp.vk"
    );

    let (payment_pk, _) = utils::read_groth_key_from_file(
        "/tmp/sanctum/payment.pk",
        "/tmp/sanctum/payment.vk"
    );

    println!("submitting on-ramp tx...");
    submit_onramp_transaction( {
        let groth_proof = onramp_circuit::generate_groth_proof(
            &onramp_pk,
            &alice_on_ramp_coin()
        );
        protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
    }).await?;

    println!("requesting merkle path...");
    let alice_merkle_proof = request_merkle_proof(0).await?;

    println!("submitting payment tx...");
    submit_payment_transaction( {
        let groth_proof = payment_circuit::generate_groth_proof(
            &payment_pk,
            &alice_input_coin(),
            &alice_output_coin(),
            &alice_merkle_proof,
            &alice_key().0
        );
        protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
    }).await?;

    Ok(())
}

fn alice_key() -> ([u8; 32], [u8; 31]) {
    let privkey = [20u8; 32];
    let pubkey =
    [
        218, 61, 173, 102, 17, 186, 176, 174, 
        54, 64, 4, 87, 114, 16, 209, 133, 
        153, 47, 114, 88, 54, 48, 138, 7,
        136, 114, 216, 152, 205, 164, 171
    ];

    (privkey, pubkey)
}

fn bob_key() -> ([u8; 32], [u8; 31]) {
    let privkey = [25u8; 32];
    let pubkey =
    [
        217, 214, 252, 243, 200, 147, 117, 28, 
        142, 219, 58, 120, 65, 180, 251, 74, 
        234, 28, 72, 194, 161, 148, 52, 219, 
        10, 34, 21, 17, 33, 38, 77,
    ];

    (privkey, pubkey)
}

// Anonymous function to generate an array
fn create_array(input: u8) -> [u8; 31] {
    let mut arr = [0; 31];
    arr[0] = input;
    arr
}

fn alice_on_ramp_coin() -> JZRecord<5> {
    let (_, _, crs) = utils::trusted_setup();

    let fields: [Vec<u8>; 5] = 
    [
        vec![0u8; 31], //entropy
        alice_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        create_array(10u8).to_vec(), //amount
        vec![0u8; 31],
    ];

    JZRecord::<5>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn alice_input_coin() -> JZRecord<5> {
    alice_on_ramp_coin()
}

fn alice_output_coin() -> JZRecord<5> {
    let (_, _, crs) = utils::trusted_setup();
    
    let fields: [Vec<u8>; 5] = 
    [
        vec![0u8; 31], //entropy
        bob_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        create_array(10u8).to_vec(), //amount
        vec![0u8; 31], //rho
    ];

    JZRecord::<5>::new(&crs, &fields, &[0u8; 31].to_vec())
}
