use std::fs::*;
use std::io::Read;

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

    let mut file = File::create(pk_file_path).unwrap();
    file.write_all(&serialized_pk).unwrap();
    println!("wrote {} bytes to {}", serialized_pk.len(), pk_file_path);

    let mut file = File::create(vk_file_path).unwrap();
    file.write_all(&serialized_vk).unwrap();
    println!("wrote {} bytes to {}", serialized_vk.len(), vk_file_path);

}

pub fn read_groth_proving_key_from_file(
    pk_file_path: &str
) -> ProvingKey<BW6_761> {

    let pk = ProvingKey::<BW6_761>::deserialize_uncompressed(
        get_file_as_byte_vec(&pk_file_path).as_slice()
    ).unwrap();
    println!("read pk from {}", pk_file_path);

    pk
}

pub fn read_groth_verification_key_from_file(
    vk_file_path: &str
) -> VerifyingKey<BW6_761> {

    let vk = VerifyingKey::<BW6_761>::deserialize_uncompressed(
        get_file_as_byte_vec(&vk_file_path).as_slice()
    ).unwrap();
    println!("read vk from {}", vk_file_path);

    vk
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    println!("read bytes from {}", filename);

    buffer
}