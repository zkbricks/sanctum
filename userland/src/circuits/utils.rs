use std::fs::*;
use std::io::Read;
use rand::SeedableRng;

use ark_serialize::*;
use ark_groth16::*;
use ark_bw6_761::{*};
use ark_ff::{
    PrimeField,
    BigInt,
    BigInteger
};

use lib_mpc_zexe::prf::JZPRFParams;
use lib_mpc_zexe::record_commitment::kzg::JZKZGCommitmentParams;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::JZVectorCommitmentParams;
use lib_mpc_zexe::record_commitment::kzg::JZRecord;

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

pub fn trusted_setup() -> (JZPRFParams, JZVectorCommitmentParams, JZKZGCommitmentParams<5>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // TODO: for now we sample the public parameters directly;
    // we should change this to load from a file produced by a trusted setup
    let prf_params = JZPRFParams::trusted_setup(&mut rng);
    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
    let crs = JZKZGCommitmentParams::<5>::trusted_setup(&mut rng);

    (prf_params, vc_params, crs)
}

pub fn bytes_to_field<F, const N: usize>(bytes: &[u8]) -> F 
    where F: PrimeField + From<BigInt<N>>
{
    F::from(BigInt::<N>::from_bits_le(bytes_to_bits(bytes).as_slice()))
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

pub fn get_dummy_utxo(crs: &JZKZGCommitmentParams<5>) -> JZRecord<5> {
    let fields: [Vec<u8>; 5] = 
    [
        vec![0u8; 31], //entropy
        vec![0u8; 31], //owner
        vec![0u8; 31], //asset id
        vec![0u8; 31], //amount
        vec![0u8; 31], //rho
    ];

    JZRecord::<5>::new(crs, &fields, &[0u8; 31].into())
}