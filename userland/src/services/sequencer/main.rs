use actix_web::{web, App, HttpServer};
use ark_ec::CurveGroup;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use ark_std::test_rng;
use std::borrow::BorrowMut;
use std::sync::Mutex;
use std::time::Instant;

use lib_mpc_zexe::vector_commitment::bytes::pedersen::*;
use lib_mpc_zexe::protocol::{self as protocol};

use lib_sanctum::merkle_update_circuit;
use lib_sanctum::utils;


// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 8;

const _ROOT_HISTORY_SIZE: u32 = 30;

#[allow(non_camel_case_types)]
pub enum PaymentGrothPublicInput {
    ROOT_X = 0, // merkle root for proving membership of input utxo
    ROOT_Y = 1, // merkle root for proving membership of input utxo
    NULLIFIER = 2, // nullifier to the input utxo
    COMMITMENT_X = 3, // commitment of the output utxo
    COMMITMENT_Y = 4, // commitment of the output utxo
}

#[allow(non_camel_case_types)]
pub enum OnrampGrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COMMITMENT_X = 2,
    COMMITMENT_Y = 3,
}


pub struct AppStateType {
    onramp_vk: VerifyingKey<BW6_761>,
    payment_vk: VerifyingKey<BW6_761>,
    merkle_update_pk: ProvingKey<BW6_761>,
    merkle_update_vk: VerifyingKey<BW6_761>,

    db: JZVectorDB<ark_bls12_377::G1Affine>, //leaves of sha256 hashes
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
        JZVectorCommitmentOpeningProof::<ark_bls12_377::G1Affine> {
            root: (*state).db.commitment(),
            record: (*state).db.get_record(index).clone(),
            path: (*state).db.proof(index),
        };

    let merkle_proof_bs58 = 
        lib_mpc_zexe::protocol::jubjub_vector_commitment_opening_proof_to_bs58(
            &merkle_proof
        );

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

    let utxo_com = ark_bls12_377::G1Affine::new(
        public_inputs[OnrampGrothPublicInput::COMMITMENT_X as usize],
        public_inputs[OnrampGrothPublicInput::COMMITMENT_Y as usize]
    );
    add_coin_to_state((*state).borrow_mut(), &utxo_com);

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

    // let stmt_root = public_inputs[PaymentGrothPublicInput::ROOT as usize];
    // let mut stmt_root_as_bytes: Vec<u8> = Vec::new();
    // stmt_root.serialize_compressed(&mut stmt_root_as_bytes).unwrap();

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

    let utxo_com = ark_bls12_377::G1Affine::new(
        public_inputs[PaymentGrothPublicInput::COMMITMENT_X as usize],
        public_inputs[PaymentGrothPublicInput::COMMITMENT_Y as usize]
    );
    add_coin_to_state((*state).borrow_mut(), &utxo_com);

    drop(state);

    "success".to_string()
}

fn initialize_state() -> AppStateType {

    let (_, vc_params, crs) = utils::trusted_setup();

    let records: Vec<ark_bls12_377::G1Affine> = (0..(1 << MERKLE_TREE_LEVELS))
        .map(|_| utils::get_dummy_utxo(&crs).commitment().into_affine())
        .collect();

    let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);


    let (_onramp_pk, onramp_vk) = lib_sanctum::onramp_circuit::circuit_setup();
    let (_payment_pk, payment_vk) = lib_sanctum::payment_circuit::circuit_setup();
    let (merkle_update_pk, merkle_update_vk) = lib_sanctum::merkle_update_circuit::circuit_setup();

    AppStateType {
        onramp_vk,
        payment_vk,
        merkle_update_pk,
        merkle_update_vk,
        db,
        num_coins: 0 
    }
}

fn add_coin_to_state(state: &mut AppStateType, com: &ark_bls12_377::G1Affine) {

    let leaf_index = (*state).num_coins;

    // add it to the frontier merkle tree
    //(*state).merkle_tree_frontier.insert(&com_as_bytes);
    // let old_merkle_proof = JZVectorCommitmentOpeningProof::<ark_bls12_377::G1Affine> {
    //     root: (*state).db.commitment(),
    //     record: (*state).db.get_record(leaf_index).clone(),
    //     path: (*state).db.proof(leaf_index),
    // };
    let old_merkle_proof = assemble_merkle_proof(state, leaf_index);

    // add it to the vector db
    (*state).db.update(leaf_index as usize, &com);
    (*state).num_coins += 1;

    // let new_merkle_proof = JZVectorCommitmentOpeningProof::<ark_bls12_377::G1Affine> {
    //     root: (*state).db.commitment(),
    //     record: (*state).db.get_record(leaf_index).clone(),
    //     path: (*state).db.proof(leaf_index),
    // };
    let new_merkle_proof = assemble_merkle_proof(state, leaf_index);

    //check the invariant that the frontier tree is consistent with the vector db
    //assert_eq!((*state).db.commitment(), (*state).merkle_tree_frontier.get_latest_root());

    let (proof, public_inputs) = merkle_update_circuit::generate_groth_proof(
        &(*state).merkle_update_pk,
        &old_merkle_proof,
        &new_merkle_proof,
        leaf_index
    );

    let valid_proof = Groth16::<BW6_761>::verify(
        &(*state).merkle_update_vk,
        &public_inputs,
        &proof
    ).unwrap();

    //assert!(valid_proof);
}


fn assemble_merkle_proof(
    state: &AppStateType,
    index: usize
) -> JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine> {
    JZVectorCommitmentOpeningProof::<ark_bls12_377::G1Affine> {
        root: state.db.commitment(),
        record: state.db.get_record(index).clone(),
        path: state.db.proof(index),
    }
}