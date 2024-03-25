use actix_web::{web, App, HttpServer};
use ark_crypto_primitives::crh::CRHScheme;
use ark_serialize::CanonicalSerialize;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use ark_std::test_rng;
use std::sync::Mutex;
use std::time::Instant;

use lib_mpc_zexe::vector_commitment::bytes::sha256::{
    FrontierMerkleTreeWithHistory,
    JZVectorDB,
    JZVectorCommitmentOpeningProof,
    JZVectorCommitmentParams
};

use lib_mpc_zexe::apps;
use lib_mpc_zexe::protocol::{self as protocol};

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 15;

const ROOT_HISTORY_SIZE: u32 = 30;

#[allow(non_camel_case_types)]
pub enum PaymentGrothPublicInput {
    ROOT = 0, // merkle root for proving membership of input utxo
    NULLIFIER = 1, // commitment of output utxo
    COMMITMENT = 2, // nullifier to the input utxo
}

#[allow(non_camel_case_types)]
pub enum OnrampGrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COMMITMENT = 2,
}


pub struct AppStateType {
    db: JZVectorDB<Vec<u8>>, //leaves of sha256 hashes
    merkle_tree_frontier: FrontierMerkleTreeWithHistory,
    num_coins: u32,
}

struct GlobalAppState {
    state: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

// queries the merkle opening proof, as the L1 contract only stores the frontier merkle tree
async fn serve_merkle_proof_request(
    global_state: web::Data<GlobalAppState>,
    index: web::Json<usize>
) -> String {
    let state = global_state.state.lock().unwrap();
    let index: usize = index.into_inner();

    let merkle_proof = JZVectorCommitmentOpeningProof::<Vec<u8>> {
        root: (*state).db.commitment(),
        record: (*state).db.get_record(index).clone(),
        path: (*state).db.proof(index),
    };

    drop(state);

    let merkle_proof_bs58 = protocol::sha2_vector_commitment_opening_proof_to_bs58(
        &merkle_proof
    );

    serde_json::to_string(&merkle_proof_bs58).unwrap()
}

async fn process_onramp_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::GrothProofBs58>
) -> String {

    let (_, vk) = apps::swap::circuit_setup();

    let now = Instant::now();

    let (groth_proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&proof.into_inner());

    let valid_proof = Groth16::<BW6_761>::verify(
        &vk,
        &public_inputs,
        &groth_proof
    ).unwrap();
    assert!(valid_proof);

    println!("proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    let mut state = global_state.state.lock().unwrap();

    // let's add all the output coins to the state
    let index: u32 = (*state).num_coins;
    let com = public_inputs[PaymentGrothPublicInput::COMMITMENT as usize];

    let mut com_as_bytes: Vec<u8> = Vec::new();
    com.serialize_uncompressed(&mut com_as_bytes).unwrap();
    println!("com_as_bytes: {:?}", com_as_bytes);

    (*state).db.update(index as usize, &com_as_bytes);
    (*state).num_coins += 1;

    drop(state);

    "success".to_string()
}

// mirrors the logic on L1 contract, but stores the entire state (rather than frontier)
async fn process_payment_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::GrothProofBs58>
) -> String {

    let (_, vk) = apps::swap::circuit_setup();

    let now = Instant::now();

    let (groth_proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&proof.into_inner());

    let valid_proof = Groth16::<BW6_761>::verify(
        &vk,
        &public_inputs,
        &groth_proof
    ).unwrap();
    assert!(valid_proof);

    println!("proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    let mut state = global_state.state.lock().unwrap();

    // let's add all the output coins to the state
    let index: u32 = (*state).num_coins;
    let com = public_inputs[PaymentGrothPublicInput::COMMITMENT as usize];

    let mut com_as_bytes: Vec<u8> = Vec::new();
    com.serialize_uncompressed(&mut com_as_bytes).unwrap();
    println!("com_as_bytes: {:?}", com_as_bytes);

    (*state).db.update(index as usize, &com_as_bytes);
    (*state).num_coins += 1;

    drop(state);

    "success".to_string()
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Note: web::Data created _outside_ HttpServer::new closure
    let app_state = web::Data::new(
        GlobalAppState {
            state: Mutex::new(initialize_state()),
        }
    );

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

fn initialize_state() -> AppStateType {

    let hash_of_zeros: Vec<u8> = <ark_crypto_primitives::crh::sha256::Sha256 as CRHScheme>::
        evaluate(&(), [0u8; 32]).unwrap();

    let records: Vec<Vec<u8>> = (0..(1 << MERKLE_TREE_LEVELS))
        .map(|_| hash_of_zeros.clone())
        .collect();

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut test_rng());
    let db = JZVectorDB::<Vec<u8>>::new(&vc_params, &records);
    
    let merkle_tree = FrontierMerkleTreeWithHistory::new(
        MERKLE_TREE_LEVELS, ROOT_HISTORY_SIZE
    );

    AppStateType { db: db, merkle_tree_frontier: merkle_tree, num_coins: 0 }
}