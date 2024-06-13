use super::types::VerifyingKey;
use ark_bls12_377::{g1::Parameters, Bls12_377, G1Affine, G2Affine};
use ark_ec::{
    short_weierstrass_jacobian::GroupProjective, AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{Fp384, QuadExtField};
use ark_std::string::String;
use ark_std::vec::Vec;
use core::str::FromStr;
extern crate alloc;

/// affine representation for given point in G1
pub fn af_g1<E>(x: &str, y: &str) -> <Bls12_377 as PairingEngine>::G1Affine
where
    E: PairingEngine,
{
    G1Affine::new(
        Fp384::from_str(x).unwrap(),
        Fp384::from_str(y).unwrap(),
        false,
    )
    .into()
}

/// affine representation for given point in G2
pub fn af_g2<E>(
    c0_x0: &str,
    c1_y0: &str,
    c0_x1: &str,
    c1_y1: &str,
) -> <Bls12_377 as PairingEngine>::G2Affine
where
    E: PairingEngine,
{
    let x = QuadExtField::new(
        Fp384::from_str(c0_x0).unwrap(),
        Fp384::from_str(c1_y0).unwrap(),
    );
    let y = QuadExtField::new(
        Fp384::from_str(c0_x1).unwrap(),
        Fp384::from_str(c1_y1).unwrap(),
    );

    G2Affine::new(x, y, false)
}

/// building a verifying key from provided strings
pub fn build_vk<E>(
    alpha_b: &[&str],
    beta_b: ([&str; 2], [&str; 2]),
    gamma_b: ([&str; 2], [&str; 2]),
    delta_b: ([&str; 2], [&str; 2]),
    gamma_abc_b: &[[alloc::string::String; 2]],
) -> VerifyingKey<Bls12_377>
where
    E: PairingEngine,
{
    let alpha = af_g1::<E>(alpha_b[0], alpha_b[1]);
    let beta = af_g2::<E>(beta_b.0[0], beta_b.0[1], beta_b.1[0], beta_b.1[1]);
    let gamma = af_g2::<E>(gamma_b.0[0], gamma_b.0[1], gamma_b.1[0], gamma_b.1[1]);
    let delta = af_g2::<E>(delta_b.0[0], delta_b.0[1], delta_b.1[0], delta_b.1[1]);

    let mut gamma_abc: Vec<GroupProjective<Parameters>> = Vec::new();
    for g in gamma_abc_b {
        gamma_abc.push(af_g1::<E>(g[0].as_str(), g[1].as_str()).into_projective());
    }

    let vk = VerifyingKey::<Bls12_377> {
        alpha_g1: alpha,
        beta_g2: beta,
        gamma_g2: gamma,
        delta_g2: delta,
        gamma_abc_g1: <Bls12_377 as PairingEngine>::G1Projective::batch_normalization_into_affine(
            gamma_abc.as_slice(),
        ),
    };

    vk
}
