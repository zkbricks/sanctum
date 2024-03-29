use std::fs::*;
use std::io::BufReader;

use ark_serialize::*;
use ark_groth16::*;
use ark_bw6_761::{*};


pub fn write_groth_key_to_file(
    pk: &ProvingKey<BW6_761>,
    pk_file_path: &str,
    vk: &VerifyingKey<BW6_761>,
    vk_file_path: &str
) {
    let mut serialized_pk = Vec::new();
    pk.serialize_uncompressed(&mut serialized_pk).unwrap();

    let mut serialized_vk = Vec::new();
    vk.serialize_uncompressed(&mut serialized_vk).unwrap();

    writeln!(
        File::create(pk_file_path).unwrap(),
        "{}",
        bs58::encode(serialized_pk).into_string()
    ).unwrap();

    writeln!(
        File::create(vk_file_path).unwrap(),
        "{}",
        bs58::encode(serialized_vk).into_string()
    ).unwrap();
}

pub fn read_groth_key_from_file(
    pk_file_path: &str,
    vk_file_path: &str
) -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    let pk_file = File::open(pk_file_path).unwrap();
    let mut pk_str = String::new();
    BufReader::new(pk_file).read_to_string(&mut pk_str).unwrap();

    let vk_file = File::open(vk_file_path).unwrap();
    let mut vk_str = String::new();
    BufReader::new(vk_file).read_to_string(&mut vk_str).unwrap();

    let vk = VerifyingKey::<BW6_761>::deserialize_uncompressed(
        bs58::decode(vk_str).into_vec().unwrap().as_slice()
    ).unwrap();

    let pk = ProvingKey::<BW6_761>::deserialize_uncompressed(
        bs58::decode(pk_str).into_vec().unwrap().as_slice()
    ).unwrap();

    (pk, vk)
}