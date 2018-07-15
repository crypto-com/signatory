//! *ring* provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;

#[cfg(feature = "ring-provider")]
mod ring_benches {
    use criterion::Criterion;
    use signatory::{
        ed25519::{FromSeed, PublicKey, Seed, Signature, Signer, Verifier, TEST_VECTORS},
        providers::ring::{Ed25519Signer, Ed25519Verifier},
        test_vector::TestVector,
    };

    /// Test vector to use for benchmarking
    const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

    fn sign(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(Seed::from_slice(TEST_VECTOR.sk).unwrap());

        c.bench_function("ring: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("ring: ed25519 verifier", move |b| {
            b.iter(|| Ed25519Verifier::verify(&public_key, TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = ring_benches;
        config = Criterion::default();
        targets = sign, verify
    }
}

#[cfg(feature = "ring-provider")]
criterion_main!(ring_benches::ring_benches);

#[cfg(not(feature = "ring-provider"))]
fn main() {
    eprintln!("*** skipping ring benchmarks: 'ring-provider' cargo feature not enabled");
}
