use actix_web::{web, App, HttpServer};

use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use std::borrow::BorrowMut;
use std::sync::Mutex;
use std::time::Instant;

use lib_sanctum::protocol;

use lib_sanctum::utils;

const _ROOT_HISTORY_SIZE: u32 = 30;


pub struct AppStateType {
    onramp_vk: VerifyingKey<BW6_761>,
    payment_vk: VerifyingKey<BW6_761>,
    merkle_update_vk: VerifyingKey<BW6_761>,
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

    // let's parse the merkle update proof
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&input_proofs.merkle_update_proof);
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).merkle_update_vk, &public_inputs, &proof).unwrap());
    println!("merkle update proof verified in {}.{} secs", 
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

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

    // let's parse the onramp proof
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&input_proofs.payment_proof);

    // let's verify the onramp proof
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).payment_vk, &public_inputs, &proof).unwrap());
    println!("onramp proof verified in {}.{} secs", 
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

    // let's parse the merkle update proof
    let (proof, public_inputs) = 
        protocol::groth_proof_from_bs58(&input_proofs.merkle_update_proof);
    let now = Instant::now();
    assert!(Groth16::<BW6_761>::verify(&(*state).merkle_update_vk, &public_inputs, &proof).unwrap());
    println!("merkle update proof verified in {}.{} secs", 
        now.elapsed().as_secs(), now.elapsed().subsec_millis());

    drop(state);
    return "OK".to_string();

}

fn initialize_state() -> AppStateType {

    let (_, vc_params, crs) = utils::trusted_setup();

    let (_, onramp_vk) = lib_sanctum::onramp_circuit::circuit_setup();
    let (_, payment_vk) = lib_sanctum::payment_circuit::circuit_setup();
    let (_, merkle_update_vk) = lib_sanctum::merkle_update_circuit::circuit_setup();

    AppStateType {
        onramp_vk,
        payment_vk,
        merkle_update_vk,
    }
}

