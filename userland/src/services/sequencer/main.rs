use actix_web::{web, App, HttpServer};
use ark_crypto_primitives::crh::CRHScheme;
use ark_serialize::CanonicalSerialize;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use ark_std::test_rng;
use lib_mpc_zexe::record_commitment::sha256::JZRecord;
use std::sync::Mutex;
use std::time::Instant;

use lib_mpc_zexe::vector_commitment::bytes::sha256::{
    FrontierMerkleTreeWithHistory,
    JZVectorDB,
    JZVectorCommitmentOpeningProof,
    JZVectorCommitmentParams
};

use lib_mpc_zexe::protocol::{self as protocol};

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;

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
    onramp_vk: VerifyingKey<BW6_761>,
    payment_vk: VerifyingKey<BW6_761>,
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

    let merkle_proof_bs58 = lib_sanctum::utils::sha2_vector_commitment_opening_proof_to_bs58(
        &merkle_proof
    );

    println!("[serve_merkle_proof_request] index: {}", index);
    println!("[serve_merkle_proof_request] root: {}", bs58::encode(merkle_proof.root).into_string());
    println!("[serve_merkle_proof_request] record: {}", bs58::encode(merkle_proof.record).into_string());

    drop(state);

    serde_json::to_string(&merkle_proof_bs58).unwrap()
}

async fn process_onramp_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::GrothProofBs58>
) -> String {

    let now = Instant::now();

    let mut state = global_state.state.lock().unwrap();

    let (groth_proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&proof.into_inner());

    let valid_proof = Groth16::<BW6_761>::verify(
        &(*state).onramp_vk,
        &public_inputs,
        &groth_proof
    ).unwrap();
    assert!(valid_proof);

    println!("proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    // let's add all the output coins to the state
    let index: u32 = (*state).num_coins;
    let com = public_inputs[OnrampGrothPublicInput::COMMITMENT as usize];

    let mut com_as_bytes: Vec<u8> = Vec::new();
    com.serialize_uncompressed(&mut com_as_bytes).unwrap();
    let com_as_bytes = com_as_bytes[0..32].to_vec();

    println!("[process_onramp_tx] record: {}", bs58::encode(&com_as_bytes).into_string());
    println!("[process_onramp_tx] previous root: {}", bs58::encode(&(*state).db.commitment()).into_string());

    (*state).db.update(index as usize, &com_as_bytes);
    (*state).num_coins += 1;

    println!("[process_onramp_tx] new root: {}", bs58::encode(&(*state).db.commitment()).into_string());

    drop(state);

    "success".to_string()
}

// mirrors the logic on L1 contract, but stores the entire state (rather than frontier)
async fn process_payment_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::GrothProofBs58>
) -> String {

    let now = Instant::now();

    let mut state = global_state.state.lock().unwrap();

    let (groth_proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&proof.into_inner());

    println!("[process_payment_tx] current root: {}", bs58::encode(&(*state).db.commitment()).into_string());

    let stmt_root = public_inputs[PaymentGrothPublicInput::ROOT as usize];
    let mut stmt_root_as_bytes: Vec<u8> = Vec::new();
    stmt_root.serialize_uncompressed(&mut stmt_root_as_bytes).unwrap();
    let stmt_root_as_bytes = stmt_root_as_bytes[0..32].to_vec();
    println!("[process_payment_tx] statement root: {}", bs58::encode(stmt_root_as_bytes).into_string());

    let valid_proof = Groth16::<BW6_761>::verify(
        &(*state).payment_vk,
        &public_inputs,
        &groth_proof
    ).unwrap();
    assert!(valid_proof);

    println!("proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

    // let's add all the output coins to the state
    let index: u32 = (*state).num_coins;
    let com = public_inputs[PaymentGrothPublicInput::COMMITMENT as usize];

    let mut com_as_bytes: Vec<u8> = Vec::new();
    com.serialize_uncompressed(&mut com_as_bytes).unwrap();
    let com_as_bytes = com_as_bytes[0..32].to_vec();

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

fn initialize_state() -> AppStateType {

    // let dummy_hash: Vec<u8> = <ark_crypto_primitives::crh::sha256::Sha256 as CRHScheme>::
    //     evaluate(&(), [0u8; 32]).unwrap();
    let dummy_hash = get_dummy_utxo().commitment();

    let records: Vec<Vec<u8>> = (0..(1 << MERKLE_TREE_LEVELS))
        .map(|_| dummy_hash.clone())
        .collect();

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut test_rng());
    let db = JZVectorDB::<Vec<u8>>::new(&vc_params, &records);
    
    let merkle_tree = FrontierMerkleTreeWithHistory::new(
        MERKLE_TREE_LEVELS, ROOT_HISTORY_SIZE
    );

    let (_onramp_pk, onramp_vk) = lib_sanctum::onramp_circuit::circuit_setup();
    let (_payment_pk, payment_vk) = lib_sanctum::payment_circuit::circuit_setup();

    AppStateType { onramp_vk, payment_vk, db, merkle_tree_frontier: merkle_tree, num_coins: 0 }
}
