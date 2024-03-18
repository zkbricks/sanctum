#![cfg(test)]

use super::{SanctumContract, SanctumContractClient};
use soroban_sdk::{Env, testutils::Logs, BytesN};

extern crate std;

#[test]
fn test_nullifier() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SanctumContract);
    let client = SanctumContractClient::new(&env, &contract_id);

    assert_eq!(client.initialize(), ());

    assert_eq!(client.insert(&env.crypto().sha256(&BytesN::from_array(&env, &[0u8; 32]).into())), 0);
    assert_eq!(client.insert(&env.crypto().sha256(&BytesN::from_array(&env, &[1u8; 32]).into())), 1);
    assert_eq!(client.insert(&env.crypto().sha256(&BytesN::from_array(&env, &[2u8; 32]).into())), 2);

    std::println!("{}", env.logs().all().join("\n"));
}
