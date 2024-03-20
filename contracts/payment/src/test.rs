#![cfg(test)]

use crate::utils;

use super::{SanctumContract, SanctumContractClient};
use soroban_sdk::{Env, testutils::Logs, BytesN};

extern crate std;

#[test]
fn test_nullifier() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SanctumContract);
    let client = SanctumContractClient::new(&env, &contract_id);

    assert_eq!(client.initialize(), ());

    let new_root = client.payment(
        &BytesN::from_array(&env, &utils::zeros(super::MERKLE_TREE_LEVELS - 1)),
        &env.crypto().sha256(&BytesN::from_array(&env, &[0u8; 32]).into()),
        &env.crypto().sha256(&BytesN::from_array(&env, &[0u8; 32]).into())
    );

    let new_root = client.payment(
        &new_root,
        &env.crypto().sha256(&BytesN::from_array(&env, &[1u8; 32]).into()),
        &env.crypto().sha256(&BytesN::from_array(&env, &[1u8; 32]).into())
    );

    let _new_root = client.payment(
        &new_root,
        &env.crypto().sha256(&BytesN::from_array(&env, &[2u8; 32]).into()),
        &env.crypto().sha256(&BytesN::from_array(&env, &[2u8; 32]).into())
    );

    std::println!("{}", env.logs().all().join("\n"));
}
