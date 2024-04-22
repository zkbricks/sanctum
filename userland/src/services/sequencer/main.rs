use actix_web::{web, App, HttpServer};
use reqwest::Client;

use ark_ec::CurveGroup;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;

use std::borrow::BorrowMut;
use std::sync::Mutex;
use std::time::Instant;

use lib_sanctum::protocol;

use lib_mpc_zexe::vector_commitment::bytes::pedersen::*;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::config::ed_on_bw6_761::MerkleTreeParams as MTParams;

use lib_sanctum::merkle_update_circuit;
use lib_sanctum::utils;

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;


pub struct AppStateType {
    onramp_vk: VerifyingKey<BW6_761>,
    payment_vk: VerifyingKey<BW6_761>,
    merkle_update_pk: ProvingKey<BW6_761>,

    db: JZVectorDB<MTParams, ark_bls12_377::G1Affine>, //leaves of sha256 hashes
    //merkle_tree_frontier: FrontierMerkleTreeWithHistory,
    num_coins: usize,
}

struct GlobalAppState {
    state: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Note: web::Data created _outside_ HttpServer::new closure
    let app_state = web::Data::new(
        GlobalAppState {
            state: Mutex::new(initialize_state()),
        }
    );
    println!("zkBricks sequencer listening for transactions...");

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(app_state.clone()) // <- register the created data
            .route("/onramp", web::post().to(process_onramp_tx))
            .route("/payment", web::post().to(process_payment_tx))
            .route("/merkle", web::get().to(serve_merkle_proof_request))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

// queries the merkle opening proof, as the L1 contract only stores the frontier merkle tree
async fn serve_merkle_proof_request(
    global_state: web::Data<GlobalAppState>,
    index: web::Json<usize>
) -> String {
    let state = global_state.state.lock().unwrap();
    let index: usize = index.into_inner();

    let merkle_proof = 
        JZVectorCommitmentOpeningProof::<MTParams, ark_bls12_377::G1Affine> {
            root: (*state).db.commitment(),
            record: (*state).db.get_record(index).clone(),
            path: (*state).db.proof(index),
        };

    let merkle_proof_bs58 = 
        protocol::jubjub_vector_commitment_opening_proof_MTEdOnBw6_761_to_bs58(
            &merkle_proof
        );

    drop(state);

    serde_json::to_string(&merkle_proof_bs58).unwrap()
}

async fn process_onramp_tx(
    global_state: web::Data<GlobalAppState>,
    input: web::Json<protocol::GrothProofBs58>
) -> String {

    let mut state = global_state.state.lock().unwrap();

    let now = Instant::now();

    // instead of blindly forwarding the proof to the verifier, let's verify it here first
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&input.clone());

    assert!(Groth16::<BW6_761>::verify(&(*state).onramp_vk, &public_inputs, &proof).unwrap());

    println!("on-ramp proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    // let's grab the utxo commitment being created by this tx
    let utxo_com = ark_bls12_377::G1Affine::new(
        public_inputs[protocol::OnrampGrothPublicInput::COMMITMENT_X as usize],
        public_inputs[protocol::OnrampGrothPublicInput::COMMITMENT_Y as usize]
    );

    // add utxo to state
    let merkle_update_proof = add_coin_to_state((*state).borrow_mut(), &utxo_com);

    drop(state);

    // let's forward the request to the verifier
    let output = protocol::OnRampProofBs58 {
        on_ramp_proof: input.clone(),
        merkle_update_proof: merkle_update_proof,
    };

    // HTTP request to transmit the output to the verifier
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8081/onramp")
        .json(&output)
        .send()
        .await
        .unwrap();

    if response.status().is_success() {
        println!("verifier successfully processed onramp tx");
        return "OK".to_string(); // TODO: this should be protocol-ized
    } else {
        println!("verifier failed to process onramp tx {:?}", response.status());
        return "FAILED".to_string(); // TODO: protocol-ize
    }
}

// mirrors the logic on L1 contract, but stores the entire state (rather than frontier)
async fn process_payment_tx(
    global_state: web::Data<GlobalAppState>,
    tx: web::Json<protocol::GrothProofBs58>
) -> String {

    let mut state = global_state.state.lock().unwrap();

    let now = Instant::now();

    // instead of blindly forwarding the proof to the verifier, let's verify it here first
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&tx.clone());

    assert!(Groth16::<BW6_761>::verify(&(*state).payment_vk, &public_inputs, &proof).unwrap());

    println!("payment proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    // let's grab the utxo commitment being created by this tx
    let utxo_com = ark_bls12_377::G1Affine::new(
        public_inputs[protocol::PaymentGrothPublicInput::COMMITMENT_X as usize],
        public_inputs[protocol::PaymentGrothPublicInput::COMMITMENT_Y as usize]
    );

    // add utxo to state
    let merkle_update_proof = add_coin_to_state((*state).borrow_mut(), &utxo_com);

    drop(state);

    // let's forward the request to the verifier
    let output = protocol::PaymentProofBs58 {
        payment_proof: tx.clone(),
        merkle_update_proof: merkle_update_proof,
    };

    // HTTP request to transmit the output to the verifier
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8081/payment")
        .json(&output)
        .send()
        .await
        .unwrap();

    if response.status().is_success() {
        println!("verifier successfully processed payment tx");
        return "OK".to_string(); // TODO: this should be protocol-ized
    } else {
        println!("verifier failed to process payment tx {:?}", response.status());
        return "FAILED".to_string(); // TODO: protocol-ize
    }
}

fn initialize_state() -> AppStateType {

    let (_, vc_params, crs) = utils::trusted_setup();

    let records: Vec<ark_bls12_377::G1Affine> = (0..(1 << MERKLE_TREE_LEVELS))
        .map(|_| utils::get_dummy_utxo(&crs).commitment().into_affine())
        .collect();

    let db = JZVectorDB::<MTParams, ark_bls12_377::G1Affine>::new(vc_params, &records);


    let (_, onramp_vk) = lib_sanctum::onramp_circuit::circuit_setup();
    let (_, payment_vk) = lib_sanctum::payment_circuit::circuit_setup();
    let (merkle_update_pk, _) = lib_sanctum::merkle_update_circuit::circuit_setup();

    AppStateType {
        onramp_vk,
        payment_vk,
        merkle_update_pk,
        db,
        num_coins: 0 
    }
}

fn add_coin_to_state(state: &mut AppStateType, com: &ark_bls12_377::G1Affine) -> protocol::GrothProofBs58 {

    let leaf_index = (*state).num_coins;

    let old_merkle_proof = assemble_merkle_proof(state, leaf_index);

    // add it to the vector db
    (*state).db.update(leaf_index as usize, &com);
    (*state).num_coins += 1;

    let new_merkle_proof = assemble_merkle_proof(state, leaf_index);

    let (proof, public_inputs) = merkle_update_circuit::generate_groth_proof(
        &(*state).merkle_update_pk,
        &old_merkle_proof,
        &new_merkle_proof,
        leaf_index
    );

    crate::protocol::groth_proof_to_bs58(&proof, &public_inputs)
}


fn assemble_merkle_proof(
    state: &AppStateType,
    index: usize
) -> JZVectorCommitmentOpeningProof<MTParams, ark_bls12_377::G1Affine> {
    JZVectorCommitmentOpeningProof::<MTParams, ark_bls12_377::G1Affine> {
        root: state.db.commitment(),
        record: state.db.get_record(index).clone(),
        path: state.db.proof(index),
    }
}