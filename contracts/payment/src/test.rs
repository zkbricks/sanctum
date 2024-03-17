#![cfg(test)]

use super::{PorobanContract, PorobanContractClient};
use soroban_sdk::{Env, testutils::Logs, BytesN};

extern crate std;

#[test]
fn test_nullifier() {
    let env = Env::default();
    let contract_id = env.register_contract(None, PorobanContract);
    let client = PorobanContractClient::new(&env, &contract_id);

    assert_eq!(client.record_nullifier(&BytesN::from_array(&env, &[0u8; 32])), 1);
    assert_eq!(client.record_nullifier(&BytesN::from_array(&env, &[1u8; 32])), 2);
    assert_eq!(client.record_nullifier(&BytesN::from_array(&env, &[2u8; 32])), 3);

    std::println!("{}", env.logs().all().join("\n"));
}
