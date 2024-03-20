#![no_std]

mod utils;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, 
    Env,
    Val, BytesN
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
    UnknownRoot = 4,
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
            env.storage().persistent().set(&DataKey::FilledSubtree(i), &BytesN::from_array(&env, &utils::zeros(i)));
        }

        // initialize the roots data structure
        // roots[0] = zeros(_levels - 1);
        env.storage().persistent().set(&DataKey::Roots(0u32), &BytesN::from_array(&env, &utils::zeros(levels - 1)));

        // nextIndex = 0;
        env.storage().persistent().set(&DataKey::NextIndex, &0u32);

        // currentRootIndex = 0;
        env.storage().persistent().set(&DataKey::CurrentRootIndex, &0u32);

        // set persistent state to mark the contract as initialized
        env.storage().persistent().set(&DataKey::Initialized, &true);

        Ok(())
    }
    
    pub fn payment(
        env: Env,
        root: BytesN<32>,
        new_coin_hash: BytesN<32>,
        old_coin_nullifier: BytesN<32>
    ) -> Result<BytesN<32>, SanctumError>
    {
        // check for double spending
        if Self::exists_nullifier(&env, &old_coin_nullifier) {
            return Err(SanctumError::DuplicateNullifier);
        }

        // check if the root (with respect to which proof is constructed) is known
        if !Self::is_known_root(&env, &root) {
            return Err(SanctumError::UnknownRoot);
        }

        // TODO: verify the zk proof

        // valid spend, so insert the new coin and nullifier
        let merkle_root = Self::insert_coin(&env, new_coin_hash)?;
        Self::insert_nullifier(&env, old_coin_nullifier)?;
        Ok(merkle_root)
    }

    fn insert_coin(env: &Env, leaf: BytesN<32>) -> Result<BytesN<32>, SanctumError>
    {
        let levels = MERKLE_TREE_LEVELS;

        // only proceed if the contract is initialized
        if !env.storage().persistent().get(&DataKey::Initialized).unwrap_or(false) {
            return Err(SanctumError::ContractUnititialized);
        }

        log!(&env, "[CONTRACTCALL] insert_coin({})", leaf);

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
                right = BytesN::from_array(&env, &utils::zeros(i));
                env.storage().persistent().set(&DataKey::FilledSubtree(i), &current_level_hash);
                //log!(&env, "setting filledSubtree({}): {}", i, current_level_hash);
            } else {
                left = env.storage().persistent().get(&DataKey::FilledSubtree(i)).unwrap();
                right = current_level_hash.clone();
            }

            current_level_hash = utils::sha256hash(&env, left, right);
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
        //log!(&env, "setting roots({}): {}", new_root_index, current_level_hash);

        //nextIndex = nextIndex + 1;
        env.storage().persistent().set(&DataKey::NextIndex, &(next_index + 1));

        Ok(current_level_hash)

    }

    fn exists_nullifier(env: &Env, nullifier: &BytesN<32>) -> bool
    {
        env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone()))
    }

    fn insert_nullifier(env: &Env, nullifier: BytesN<32>) -> Result<(), SanctumError>
    {
        log!(&env, "[CONTRACTCALL] insert_nullifier({})", nullifier);

        if !env.storage().persistent().get(&DataKey::Initialized).unwrap_or(false) {
            return Err(SanctumError::ContractUnititialized);
        }

        // if the nullifier exists, then we are witnessing an attempt to double spend
        if env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone())) {
            return Err(SanctumError::DuplicateNullifier);
        }

        // record the nullifier
        env.storage().persistent().set(&DataKey::Nullifier(nullifier.clone()), &Val::VOID);

        Ok(())
    }

    fn is_known_root(env: &Env, root: &BytesN<32>) -> bool
    {
        let current_root_index: u32 = env.storage().persistent().get(&DataKey::CurrentRootIndex).unwrap();
        let mut i = current_root_index;

        loop {
            let root_at_i: BytesN<32> = env.storage().persistent().get(&DataKey::Roots(i)).unwrap();
            if *root == root_at_i { return true; }
            if i == 0 { i = ROOT_HISTORY_SIZE; }
            i = i - 1;
            if i == current_root_index { break; }
        }

        return false;
    }
}

mod test;
