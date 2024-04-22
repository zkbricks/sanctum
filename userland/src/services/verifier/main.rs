use actix_web::{web, App, HttpServer};

use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use lib_sanctum::protocol;

const ROOT_HISTORY_SIZE: u32 = 30;


pub struct AppStateType {
    onramp_vk: VerifyingKey<BW6_761>,
    payment_vk: VerifyingKey<BW6_761>,
    merkle_update_vk: VerifyingKey<BW6_761>,
    merkle_root_history: MerkleRootHistory,
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
    println!("zkBricks verifier listening for transactions...");

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(app_state.clone()) // <- register the created data
            .route("/onramp", web::post().to(process_onramp_tx))
            .route("/payment", web::post().to(process_payment_tx))
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}

async fn process_onramp_tx(
    global_state: web::Data<GlobalAppState>,
    input: web::Json<protocol::OnRampProofBs58>
) -> String {

    let mut state = global_state.state.lock().unwrap();

    let input_proofs = input.into_inner();

    // let's parse the onramp proof
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&input_proofs.on_ramp_proof);

    // let's verify the onramp proof
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).onramp_vk, &public_inputs, &proof).unwrap());
    println!("onramp proof verified in {}.{} secs", 
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

    // record the new merkle root if it extends the old root
    update_merkle_root(state.borrow_mut(), &input_proofs.merkle_update_proof);

    drop(state);
    return "OK".to_string();

}

// mirrors the logic on L1 contract, but stores the entire state (rather than frontier)
async fn process_payment_tx(
    global_state: web::Data<GlobalAppState>,
    input: web::Json<protocol::PaymentProofBs58>
) -> String {

    let mut state = global_state.state.lock().unwrap();

    let input_proofs = input.into_inner();

    // check if proof is constructed w.r.t. a known merkle root
    let claimed_root_x = input_proofs
        .payment_proof
        .public_inputs[protocol::PaymentGrothPublicInput::ROOT_X as usize]
        .clone();
    let claimed_root_y = input_proofs
        .payment_proof
        .public_inputs[protocol::PaymentGrothPublicInput::ROOT_Y as usize]
        .clone();
    assert!(state.merkle_root_history.is_known_root(&(claimed_root_x, claimed_root_y)));

    // let's parse the onramp proof
    let (proof, public_inputs) =
        protocol::groth_proof_from_bs58(&input_proofs.payment_proof);

    // let's verify the payment proof
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).payment_vk, &public_inputs, &proof).unwrap());
    println!("payment proof verified in {}.{} secs",
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

    // record the new merkle root if it extends the old root
    update_merkle_root(state.borrow_mut(), &input_proofs.merkle_update_proof);

    drop(state);
    return "OK".to_string();

}

fn update_merkle_root(state: &mut AppStateType, merkle_update_proof: &protocol::GrothProofBs58) {
    // check that we are extending from the latest old root
    if let Some(latest_root) = state.merkle_root_history.get_latest_root() {
        let old_root_x = merkle_update_proof
            .public_inputs[protocol::MerkleUpdateGrothPublicInput::OLD_ROOT_X as usize]
            .clone();
        let old_root_y = merkle_update_proof
            .public_inputs[protocol::MerkleUpdateGrothPublicInput::OLD_ROOT_Y as usize]
            .clone();

        assert!(latest_root == (old_root_x, old_root_y));
    } // else is for the first ever root

    // let's parse the merkle update proof
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&merkle_update_proof);

    // verify the proof
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).merkle_update_vk, &public_inputs, &proof).unwrap());
    println!("merkle update proof verified in {}.{} secs\n",
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

    // store the new root
    let new_root_x = merkle_update_proof
    .public_inputs[protocol::MerkleUpdateGrothPublicInput::NEW_ROOT_X as usize]
    .clone();
    let new_root_y = merkle_update_proof
        .public_inputs[protocol::MerkleUpdateGrothPublicInput::NEW_ROOT_Y as usize]
        .clone();

    state.merkle_root_history.insert(&(new_root_x, new_root_y));

}

fn initialize_state() -> AppStateType {
    let (_, onramp_vk) = lib_sanctum::onramp_circuit::circuit_setup();
    let (_, payment_vk) = lib_sanctum::payment_circuit::circuit_setup();
    let (_, merkle_update_vk) = lib_sanctum::merkle_update_circuit::circuit_setup();

    AppStateType {
        onramp_vk,
        payment_vk,
        merkle_update_vk,
        merkle_root_history: MerkleRootHistory::new(ROOT_HISTORY_SIZE),
    }
}

// base58 encoded (x,y) coordinates
type Hash = (String, String);

pub struct MerkleRootHistory {
    pub root_history_size: u32,
    historical_roots: HashMap<u32, Hash>,
    next_root_index: u32,
}

impl MerkleRootHistory {

    // create a new merkle tree with no leaves
    pub fn new(root_history_size: u32) -> Self
    {
        MerkleRootHistory {
            root_history_size,
            historical_roots: HashMap::new(),
            next_root_index: 0,
        }
    }

    // insert a new leaf into the merkle tree
    pub fn insert(&mut self, root: &Hash) {
        self.historical_roots.insert(self.next_root_index , root.clone());
        self.next_root_index = (self.next_root_index + 1) % self.root_history_size;
    }

    pub fn is_known_root(&self, root: &Hash) -> bool {
        let start_index = self.next_root_index - 1;
        let mut i = start_index;

        loop {
            if !self.historical_roots.contains_key(&i) { return false; }
            if self.historical_roots.get(&i).unwrap() == root { return true; }

            if i == 0 { i = self.root_history_size; }
            i = i - 1;

            if i == start_index { break; } // have we tried everything?
        }

        return false;
    }

    pub fn get_latest_root(&self) -> Option<Hash> {
        let last_index: u32 = self.next_root_index - 1;
        return self.historical_roots.get(&last_index).cloned();
    }
}

