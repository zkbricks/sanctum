#![no_std]

use soroban_sdk::
{
    *,
    contract, contracterror, contractimpl, contracttype, log, 
    Env,
    Val, Bytes, BytesN
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Vk,
}

mod groth16_verifier;
use groth16_verifier::*;

#[contract]
pub struct SanctumVerifier;

#[contractimpl]
impl SanctumVerifier {
    pub fn init(env: Env, vk_hash: BytesN<32>) {
        env.storage().persistent().set(&DataKey::Vk, &vk_hash)
    }

    pub fn verify(env: Env, key: Bytes, proof: Bytes, image: Vec<Bytes>) -> bool {
        let vk_hash = env.storage().persistent().get(&DataKey::Vk).unwrap();
        let verifier = SorobanGroth16Verifier::load_with_vk_hash(vk_hash);

        verifier.verify(&env, key, proof, image)
    }
}

