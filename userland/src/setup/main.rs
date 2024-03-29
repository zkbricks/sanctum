use lib_sanctum::{ payment_circuit, onramp_circuit, utils};

#[tokio::main]
async fn main() -> reqwest::Result<()> {
    //parse_args();
    std::fs::create_dir_all("/tmp/sanctum").unwrap();

    println!("initiating circuit setup for onramp circuit...");
    let (onramp_pk, onramp_vk) = onramp_circuit::circuit_setup();
    utils::write_groth_key_to_file(&onramp_pk, "/tmp/sanctum/onramp.pk", &onramp_vk, "/tmp/sanctum/onramp.vk");

    println!("initiating circuit setup for payment circuit...");
    let (payment_pk, payment_vk) = payment_circuit::circuit_setup();
    utils::write_groth_key_to_file(&payment_pk, "/tmp/sanctum/payment.pk", &payment_vk, "/tmp/sanctum/payment.vk");

    println!("completed trusted setup...");

    Ok(())
}
