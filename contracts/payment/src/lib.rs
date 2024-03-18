#![no_std]
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

    fn sha256hash(env: &Env, left: BytesN<32>, right: BytesN<32>) -> BytesN<32>
    {
        let mut concatenated: BytesN<64> = BytesN::from_array(&env, &[0u8; 64]);

        for (i,b) in left.iter().enumerate() {
            concatenated.set(i as u32, b);
        }
        for (i,b) in right.iter().enumerate() {
            concatenated.set(i as u32 + 32, b);
        }

        env.crypto().sha256(&concatenated.into())
    }
}

fn zeros(i: u32) -> [u8; 32] {

    // zeros(0) = H([0; 32])
    // zeros(i) = H(zeros(i-1) || zeros(i-1))
    // the following values are pre-computed for efficiency

    return match i {
        0 => [102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37, ],
        1 => [46, 235, 116, 166, 23, 127, 88, 141, 128, 192, 199, 82, 185, 149, 86, 144, 45, 223, 150, 130, 208, 185, 6, 245, 170, 42, 219, 175, 132, 102, 164, 233, ],
        2 => [18, 35, 52, 154, 64, 210, 238, 16, 189, 27, 235, 181, 136, 158, 248, 1, 140, 139, 193, 51, 89, 237, 148, 179, 135, 129, 10, 249, 108, 110, 66, 104, ],
        3 => [91, 130, 182, 149, 167, 172, 38, 104, 225, 136, 183, 95, 125, 79, 167, 159, 170, 80, 65, 23, 209, 253, 252, 190, 138, 70, 145, 92, 26, 138, 81, 145, ],
        4 => [12, 33, 31, 155, 83, 132, 198, 136, 72, 162, 9, 172, 31, 147, 144, 83, 48, 18, 140, 183, 16, 174, 88, 55, 121, 192, 113, 39, 239, 136, 255, 92, ],
        5 => [86, 70, 10, 128, 225, 23, 30, 36, 172, 29, 205, 192, 211, 241, 10, 79, 51, 191, 49, 118, 98, 96, 171, 10, 222, 28, 126, 176, 220, 188, 93, 112, ],
        6 => [45, 234, 47, 196, 13, 0, 229, 176, 175, 139, 236, 83, 100, 62, 43, 182, 134, 20, 245, 48, 189, 12, 107, 146, 125, 62, 94, 217, 113, 115, 65, 123, ],
        7 => [238, 147, 93, 207, 2, 94, 48, 22, 87, 158, 195, 159, 207, 222, 165, 104, 138, 180, 202, 95, 59, 84, 114, 106, 195, 149, 119, 26, 101, 141, 46, 161, ],
        8 => [16, 164, 17, 186, 189, 114, 163, 191, 156, 159, 130, 121, 62, 115, 113, 247, 133, 57, 193, 184, 10, 43, 193, 55, 145, 189, 200, 216, 184, 94, 55, 147, ],
        9 => [161, 92, 74, 146, 45, 153, 153, 114, 120, 97, 39, 148, 167, 199, 64, 70, 159, 123, 69, 222, 246, 190, 242, 98, 226, 238, 194, 112, 61, 24, 114, 231, ],
        10 => [134, 231, 110, 32, 28, 46, 173, 136, 184, 189, 237, 11, 35, 145, 46, 67, 26, 27, 171, 200, 158, 241, 81, 229, 5, 67, 134, 34, 53, 11, 217, 145, ],
        11 => [199, 254, 9, 197, 103, 191, 18, 209, 121, 255, 207, 134, 83, 166, 78, 29, 13, 207, 17, 147, 143, 212, 68, 57, 159, 213, 70, 32, 162, 237, 247, 249, ],
        12 => [7, 239, 118, 89, 255, 22, 209, 75, 97, 87, 131, 25, 231, 217, 64, 94, 201, 203, 197, 196, 112, 217, 135, 207, 180, 38, 238, 213, 21, 165, 250, 80, ],
        13 => [183, 194, 250, 114, 94, 56, 155, 81, 121, 169, 155, 198, 89, 197, 97, 180, 199, 136, 28, 202, 148, 61, 68, 145, 34, 205, 181, 98, 23, 56, 91, 13, ],
        14 => [213, 54, 208, 42, 230, 160, 167, 39, 166, 233, 7, 178, 250, 252, 113, 87, 117, 68, 210, 86, 228, 219, 95, 47, 34, 213, 190, 223, 115, 192, 205, 124, ],
        15 => [170, 76, 66, 240, 158, 203, 88, 167, 102, 126, 26, 39, 182, 68, 178, 212, 188, 159, 180, 33, 60, 248, 60, 206, 110, 89, 53, 11, 190, 71, 123, 157, ],
        16 => [46, 212, 55, 49, 73, 161, 221, 104, 134, 142, 29, 119, 218, 8, 42, 121, 202, 173, 71, 11, 108, 184, 15, 153, 244, 169, 119, 48, 195, 39, 173, 111, ],
        17 => [174, 115, 59, 102, 247, 14, 138, 133, 46, 215, 91, 141, 19, 127, 253, 192, 17, 178, 51, 39, 139, 47, 55, 38, 121, 194, 91, 83, 130, 180, 119, 245, ],
        18 => [242, 252, 117, 23, 169, 157, 88, 11, 192, 169, 112, 235, 249, 137, 105, 181, 51, 212, 213, 146, 156, 16, 224, 219, 145, 215, 239, 90, 167, 36, 222, 11, ],
        19 => [72, 71, 235, 143, 116, 170, 64, 123, 171, 181, 24, 219, 74, 55, 206, 248, 54, 61, 253, 30, 22, 121, 215, 40, 147, 183, 74, 243, 151, 56, 224, 171, ],
        20 => [121, 152, 129, 117, 0, 25, 202, 57, 81, 89, 65, 160, 2, 49, 114, 149, 20, 202, 64, 41, 73, 138, 12, 103, 94, 157, 102, 160, 244, 52, 1, 3, ],
        21 => [30, 124, 214, 126, 70, 31, 128, 172, 219, 180, 194, 157, 205, 228, 67, 218, 86, 88, 158, 203, 156, 218, 124, 119, 120, 229, 131, 230, 80, 132, 73, 52, ],
        22 => [65, 23, 226, 189, 174, 208, 97, 33, 228, 22, 6, 214, 22, 179, 175, 133, 143, 149, 111, 33, 149, 199, 8, 240, 228, 116, 18, 110, 113, 27, 23, 201, ],
        23 => [49, 91, 134, 79, 184, 105, 68, 183, 93, 80, 188, 40, 94, 61, 121, 179, 247, 62, 74, 240, 74, 132, 76, 208, 238, 131, 48, 95, 142, 130, 91, 76, ],
        24 => [157, 200, 109, 203, 129, 69, 200, 43, 31, 13, 166, 208, 200, 211, 242, 125, 165, 130, 115, 83, 202, 109, 183, 171, 249, 203, 245, 29, 63, 176, 219, 136, ],
        25 => [69, 122, 131, 172, 4, 231, 148, 188, 186, 19, 255, 120, 96, 33, 135, 227, 35, 65, 22, 4, 127, 123, 211, 148, 34, 25, 225, 29, 223, 233, 196, 205, ],
        26 => [67, 169, 77, 37, 69, 78, 245, 148, 92, 252, 169, 194, 42, 63, 76, 147, 163, 118, 84, 52, 198, 207, 153, 28, 113, 250, 41, 170, 192, 214, 105, 158, ],
        27 => [246, 187, 222, 113, 112, 31, 93, 106, 205, 59, 133, 200, 252, 152, 50, 87, 22, 19, 171, 162, 111, 36, 66, 55, 17, 255, 239, 133, 238, 39, 113, 243, ],
        28 => [225, 71, 31, 118, 13, 200, 128, 145, 78, 81, 29, 93, 8, 5, 174, 42, 41, 62, 235, 23, 252, 164, 71, 7, 27, 161, 226, 105, 76, 196, 87, 50, ],
        29 => [109, 1, 230, 101, 139, 148, 178, 204, 24, 96, 94, 134, 118, 30, 153, 22, 68, 159, 250, 184, 35, 3, 8, 212, 163, 205, 157, 240, 145, 233, 1, 102, ],
        30 => [207, 230, 210, 13, 5, 148, 105, 194, 218, 118, 72, 211, 174, 90, 20, 88, 253, 145, 162, 238, 136, 9, 94, 253, 206, 103, 93, 105, 76, 128, 159, 110, ],
        31 => [69, 175, 119, 140, 97, 198, 250, 216, 127, 82, 200, 35, 250, 198, 110, 8, 228, 201, 46, 66, 249, 38, 229, 248, 234, 203, 126, 15, 52, 155, 208, 81, ],
        _ => panic!("invalid index for zeros() function")
    };

}

mod test;
