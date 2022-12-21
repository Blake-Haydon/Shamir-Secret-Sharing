use std::ops::{Add, AddAssign, Mul, MulAssign};

mod arithmetic;
use arithmetic::{FieldElement, SecretShare};

// 2^31 - 1 Mersenne prime
const P: u32 = 2147483647;

/// Generate `n` shares of a secret using Shamir's Secret Sharing Scheme with a threshold of `k`.
/// The `secret` is a u32.
fn gen_shares(n: usize, k: usize, secret: u32) -> Vec<SecretShare> {
    // Generate random coefficients (a0 = secret)
    // akx^k + ... + a2x^2 + a1x + a0
    // !vec[ak, a(k-1), ..., a2, a1, a0]
    let mut coefficients: Vec<FieldElement> = Vec::new();
    for _ in 1..k {
        coefficients.push(FieldElement::rand(P));
    }
    coefficients.push(FieldElement::new(secret, P));

    // Generate shares by evaluating polynomial at x = 1, 2, ..., n
    let mut shares: Vec<SecretShare> = Vec::new();
    for i in 1..(n + 1) {
        let x = FieldElement::new(i as u32, P);
        let y = poly_eval(&coefficients, x);
        shares.push(SecretShare { x, y });
    }

    return shares;
}

/// Reconstruct the secret from shares using Lagrange interpolation, where `k` is the threshold.
fn reconstruct_secret(k: usize, shares: Vec<SecretShare>) -> u32 {
    assert!(
        shares.len() >= k,
        "There must be more shares than the threshold"
    );

    let mut reconstructed_secret = FieldElement::new(0, P);
    for j in 0..shares.len() {
        let mut delta = FieldElement::new(1, P);
        for k in 0..shares.len() {
            if k != j {
                delta *= -shares[k].x / (shares[j].x - shares[k].x);
            }
        }
        reconstructed_secret += delta * shares[j].y;
    }

    return reconstructed_secret.value;
}

/// Evaluate a polynomial at x using Horner's method in the form of akx^k + ... + a2x^2 + a1x + a0
fn poly_eval<T: Add<Output = T> + Mul<Output = T> + AddAssign + MulAssign + Copy>(
    coefficients: &Vec<T>,
    x: T,
) -> T {
    let mut y: T = coefficients[coefficients.len() - 1];
    let mut x_acc: T = x;
    for i in 1..coefficients.len() {
        y += coefficients[coefficients.len() - 1 - i] * x_acc;
        x_acc *= x;
    }

    return y;
}

fn main() {
    // Define constants to be used in secret generation and evaluation
    const NUM_SHARES: usize = 5;
    const NUM_THRESHOLD: usize = 3;
    const SECRET: u32 = 123456789;

    // Generate shares
    let shares = gen_shares(NUM_SHARES, NUM_THRESHOLD, SECRET);
    for i in 0..shares.len() {
        println!(
            "Share {}: ({}, {})",
            i + 1,
            shares[i].x.value,
            shares[i].y.value,
        );
    }

    // Reconstruct secret
    let rec_secret = reconstruct_secret(NUM_THRESHOLD, shares[1..4].to_vec());
    println!("Reconstructed Secret: {:?}", rec_secret);
}
