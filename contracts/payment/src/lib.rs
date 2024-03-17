#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, 
    Env,
    Val, BytesN
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PorobanError {
    DuplicateNullifier = 1,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    NullifierCnt,
    Nullifier(BytesN<32>),
}

#[contract]
pub struct PorobanContract;

#[contractimpl]
impl PorobanContract {
    pub fn record_nullifier(env: Env, nullifier: BytesN<32>) -> Result<u32, PorobanError> {

        // if no value, then let's start at 0
        let mut count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::NullifierCnt)
            .unwrap_or(0);
        log!(&env, "count: {}", count);

        // if the nullifier exists, then we are witnessing an attempt to double spend
        if env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone())) {
            return Err(PorobanError::DuplicateNullifier);
        }

        // record the nullifier
        env
            .storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &Val::VOID);
        log!(&env, "nullifier: {}", nullifier);

        // Increment the count.
        count += 1;

        // Save the count.
        env.storage().persistent().set(&DataKey::NullifierCnt, &count);

        Ok(count)
    }
}

mod test;
