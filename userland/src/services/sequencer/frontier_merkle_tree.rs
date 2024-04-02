
use std::collections::HashMap;

use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme};
use ark_serialize::*;

type LeafH = Sha256;
type CompressH = Sha256;
type Hash = Vec<u8>;

pub struct FrontierMerkleTreeWithHistory {
    pub levels: u32,
    pub root_history_size: u32,
    filled_subtrees: HashMap<u32, Hash>,
    historical_roots: HashMap<u32, Hash>,
    current_root_index: u32,
    next_index: u32,
}

pub fn compute_leaf_hash(leaf: &[u8]) -> Hash {
    let mut serialized_leaf: Vec<u8> = Vec::new();
    leaf.serialize_uncompressed(&mut serialized_leaf).unwrap();
    <LeafH as CRHScheme>::evaluate(&(), serialized_leaf).unwrap()
}

fn zeros(level: u32) -> Vec<u8> {
    if level == 0 {
        // to_uncompressed_bytes([0; 32]) adds length of 32 to serialized_zeros
        return compute_leaf_hash(&vec![0u8; 32]);
    } else {
        // H(zeros(level - 1) || zeros(level - 1))
        let zeros_level_minus_1 = zeros(level - 1);
        return <CompressH as TwoToOneCRHScheme>::compress(
            &(),
            &zeros_level_minus_1,
            &zeros_level_minus_1
        ).unwrap()
    };
}

impl FrontierMerkleTreeWithHistory {

    // create a new merkle tree with no leaves
    pub fn new(
        levels: u32,
        root_history_size: u32,
    ) -> Self
    {
        assert!(levels > 0, "levels must be greater than 0");
        assert!(levels < 32, "levels must be less than 32");

        let mut filled_subtrees: HashMap<u32, Hash> = HashMap::new();
        let mut historical_roots: HashMap<u32, Hash> = HashMap::new();

        for i in 0..levels {
            println!("[FrontierMerkleTreeWithHistory.new] filled_subtrees.insert({}, {})",
                i, bs58::encode(zeros(i)).into_string());
            filled_subtrees.insert(i, zeros(i));
        }

        println!("[FrontierMerkleTreeWithHistory.new] historical_roots.insert({}, {})",
            0, bs58::encode(zeros(levels - 1)).into_string());
        historical_roots.insert(0, zeros(levels - 1));

        FrontierMerkleTreeWithHistory {
            levels,
            root_history_size,
            filled_subtrees,
            historical_roots,
            current_root_index: 0,
            next_index: 0,
        }
    }

    // insert a new leaf into the merkle tree
    pub fn insert(&mut self, leaf: &Hash) {
        assert!(self.next_index < (1 << self.levels), "Merkle tree is full");

        let mut current_index = self.next_index;

        let mut current_level_hash = compute_leaf_hash(leaf);
        let mut left: Hash;
        let mut right: Hash;

        for i in 0..self.levels {
            if current_index % 2 == 0 { //left child
                left = current_level_hash.clone();
                right = zeros(i); // H(to_uncompressed_bytes([0; 32]))
                println!("[FrontierMerkleTreeWithHistory] filled_subtrees.insert({}, {})",
                    i, bs58::encode(current_level_hash.clone()).into_string());
                self.filled_subtrees.insert(i, current_level_hash);
            } else { //right child
                left = self.filled_subtrees.get(&i).unwrap().clone();
                right = current_level_hash.clone();
            }

            current_level_hash = <CompressH as TwoToOneCRHScheme>::compress(
                &(),
                &left,
                &right
            ).unwrap();

            current_index /= 2;
        }

        let new_root_index = (self.current_root_index + 1) % self.root_history_size;
        self.current_root_index = new_root_index;
        println!("[FrontierMerkleTreeWithHistory.insert] historical_roots.insert({}, {})",
            new_root_index, bs58::encode(current_level_hash.clone()).into_string());
        self.historical_roots.insert(new_root_index, current_level_hash);
        self.next_index += 1;
    }

    pub fn is_known_root(&self, root: &Hash) -> bool {
        let current_root_index = self.current_root_index;
        let mut i = current_root_index;

        loop {
            if root == self.historical_roots.get(&i).unwrap() { return true; }
            if i == 0 { i = self.root_history_size; }
            i = i - 1;
            if i == current_root_index { break; }
        }

        return false;
    }

    pub fn get_latest_root(&self) -> Hash {
        self.historical_roots.get(&self.current_root_index).unwrap().clone()
    }
}

