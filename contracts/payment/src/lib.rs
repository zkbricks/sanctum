#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, 
    Env,
    Val, BytesN,
};

// define the depth of the merkle tree as a constant
const MERKLE_TREE_LEVELS: u32 = 15;

// how many historical roots to store
const ROOT_HISTORY_SIZE: u32 = 30;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SanctumError {
    ContractUnititialized = 1,
    IllegalContractCall = 2,
    DuplicateNullifier = 3,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Initialized,
    FilledSubtree(u32),
    Roots(u32),
    NextIndex,
    CurrentRootIndex,
    Nullifier(BytesN<32>),
}

#[contract]
pub struct SanctumContract;

#[contractimpl]
impl SanctumContract {

    pub fn initialize(env: Env) -> Result<(), SanctumError>
    {
        let levels = MERKLE_TREE_LEVELS;
        // only proceed if the contract is uninitialized
        if env.storage().persistent().get(&DataKey::Initialized).unwrap_or(false) {
            return Err(SanctumError::IllegalContractCall);
        }

        // initialize the filledSubtrees data structure 
        // for (uint32 i = 0; i < _levels; i++) {
        //   filledSubtrees[i] = zeros(i);
        // }
        for i in 0..levels {
            env.storage().persistent().set(&DataKey::FilledSubtree(i), &BytesN::from_array(&env, &zeros(i)));
        }

        // initialize the roots data structure
        // roots[0] = zeros(_levels - 1);
        env.storage().persistent().set(&DataKey::Roots(0u32), &BytesN::from_array(&env, &zeros(levels - 1)));

        // nextIndex = 0;
        env.storage().persistent().set(&DataKey::NextIndex, &0u32);

        // currentRootIndex = 0;
        env.storage().persistent().set(&DataKey::CurrentRootIndex, &0u32);

        // set persistent state to mark the contract as initialized
        env.storage().persistent().set(&DataKey::Initialized, &true);

        Ok(())
    }

    pub fn insert(env: Env, leaf: BytesN<32>) -> Result<u32, SanctumError>
    {
        let levels = MERKLE_TREE_LEVELS;

        // only proceed if the contract is initialized
        if !env.storage().persistent().get(&DataKey::Initialized).unwrap_or(false) {
            return Err(SanctumError::ContractUnititialized);
        }

        // since the contract is initialized, it's safe to assume
        // that the state variable NextIndex exists
        let next_index: u32 = env.storage().persistent().get(&DataKey::NextIndex).unwrap();
        let mut current_index = next_index;
        let mut current_level_hash = leaf;

        let mut left: BytesN<32>;
        let mut right: BytesN<32>;

        // calculate the new root
        for i in 0..levels {
            if current_index % 2 == 0 {
                left = current_level_hash.clone();
                right = BytesN::from_array(&env, &zeros(i));
                env.storage().persistent().set(&DataKey::FilledSubtree(i), &BytesN::from_array(&env, &zeros(i)));
            } else {
                left = env.storage().persistent().get(&DataKey::FilledSubtree(i)).unwrap();
                right = current_level_hash.clone();
            }

            current_level_hash = Self::sha256hash(&env, left, right);
            current_index = current_index / 2;
        }

        // since the contract is initialized, it's safe to assume
        // that the state variable CurrentRootIndex exists
        let current_root_index: u32 = env.storage().persistent().get(&DataKey::CurrentRootIndex).unwrap();

        //uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        let new_root_index = (current_root_index + 1) % ROOT_HISTORY_SIZE;

        //currentRootIndex = newRootIndex;
        env.storage().persistent().set(&DataKey::CurrentRootIndex, &new_root_index);

        //roots[newRootIndex] = currentLevelHash;
        env.storage().persistent().set(&DataKey::Roots(new_root_index), &current_level_hash);

        //nextIndex = nextIndex + 1;
        env.storage().persistent().set(&DataKey::NextIndex, &(next_index + 1));

        Ok(next_index)

    }

    pub fn record_nullifier(env: Env, nullifier: BytesN<32>) -> Result<(), SanctumError>
    {
        if !env.storage().persistent().get(&DataKey::Initialized).unwrap_or(false) {
            return Err(SanctumError::ContractUnititialized);
        }

        // if the nullifier exists, then we are witnessing an attempt to double spend
        if env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone())) {
            return Err(SanctumError::DuplicateNullifier);
        }

        // record the nullifier
        env.storage().persistent().set(&DataKey::Nullifier(nullifier.clone()), &Val::VOID);
        log!(&env, "nullifier: {}", nullifier);

        Ok(())
    }

    pub fn compute_hash(env: Env, left: BytesN<32>, right: BytesN<32>)
    {
        let mut concatenated: BytesN<64> = BytesN::from_array(&env, &[0u8; 64]);
        for (i,b) in left.iter().enumerate() {
            concatenated.set(i.try_into().unwrap(), b);
        }
        for (i,b) in right.iter().enumerate() {
            concatenated.set(i as u32 + 32, b);
        }

        let hash = env.crypto().sha256(&concatenated.into());
        log!(&env, "SHA256(left || right): {}", hash);


        let h_left = env.crypto().sha256(&left.into());
        let mut concatenated: BytesN<64> = BytesN::from_array(&env, &[0u8; 64]);
        for (i,b) in h_left.iter().enumerate() {
            concatenated.set(i.try_into().unwrap(), b);
        }
        for (i,b) in right.iter().enumerate() {
            concatenated.set(i as u32 + 32, b);
        }

        let hash = env.crypto().sha256(&concatenated.into());
        log!(&env, "SHA256(SHA256(left) || right): {}", hash);
    }

    fn sha256hash(env: &Env, left: BytesN<32>, right: BytesN<32>) -> BytesN<32>
    {
        let h_left = env.crypto().sha256(&left.into());
        let mut concatenated: BytesN<64> = BytesN::from_array(&env, &[0u8; 64]);
        for (i,b) in h_left.iter().enumerate() {
            concatenated.set(i.try_into().unwrap(), b);
        }
        for (i,b) in right.iter().enumerate() {
            concatenated.set(i as u32 + 32, b);
        }

        env.crypto().sha256(&concatenated.into())
    }
}

fn zeros(i: u32) -> [u8; 32] {
    return match i {
        0 => [0u8; 32],
        1 => [0u8; 32],
        2 => [0u8; 32],
        3 => [0u8; 32],
        4 => [0u8; 32],
        5 => [0u8; 32],
        6 => [0u8; 32],
        7 => [0u8; 32],
        8 => [0u8; 32],
        9 => [0u8; 32],
        10 => [0u8; 32],
        11 => [0u8; 32],
        12 => [0u8; 32],
        13 => [0u8; 32],
        14 => [0u8; 32],
        15 => [0u8; 32],
        _ => [0u8; 32],
    };

}

mod test;
