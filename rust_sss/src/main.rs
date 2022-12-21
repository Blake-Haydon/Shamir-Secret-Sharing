use openssl::rand::rand_bytes;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub};

// 2^31 - 1 Mersenne prime
const P: u32 = 2147483647;

#[derive(Debug, Copy, Clone)]
struct SecretShare {
    x: FieldElement,
    y: FieldElement,
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct FieldElement {
    value: u32,
    prime: u32,
}

impl FieldElement {
    fn new(value: u32, prime: u32) -> FieldElement {
        // TODO: add Result for non prime numbers and values greater than prime
        return FieldElement {
            value: value % prime, // TODO: fix this hack: do not permit values larger than the prime
            prime,
        };
    }

    fn rand(prime: u32) -> FieldElement {
        return FieldElement {
            value: rand_u32() % prime,
            prime,
        };
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.prime == other.prime,
            "Cannot add two numbers in different Fields"
        );

        let a = self.value as u64;
        let b = other.value as u64;
        let p = self.prime as u64;

        Self {
            value: ((a + b) % p) as u32,
            prime: self.prime,
        }
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.prime == other.prime,
            "Cannot add two numbers in different Fields"
        );

        let a = self.value as u64;
        let b = other.value as u64;
        let p = self.prime as u64;

        self.value = ((a + b) % p) as u32;
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        assert!(
            self.prime == other.prime,
            "Cannot subtract two numbers in different Fields"
        );

        let a = self.value as u64;
        let b = other.value as u64;
        let p = self.prime as u64;

        Self {
            value: ((a + p - b) % p) as u32,
            prime: self.prime,
        }
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            value: self.prime - self.value,
            prime: self.prime,
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        assert!(
            self.prime == other.prime,
            "Cannot multiply two numbers in different Fields"
        );

        let a = self.value as u64;
        let b = other.value as u64;
        let p = self.prime as u64;
        return FieldElement {
            value: ((a * b) % p) as u32,
            prime: self.prime,
        };
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, other: Self) {
        assert!(
            self.prime == other.prime,
            "Cannot multiply two numbers in different Fields"
        );
        let a = self.value as u64;
        let b = other.value as u64;
        let p = self.prime as u64;

        self.value = ((a * b) % p) as u32;
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        // Find multiplicative inverse of b
        // TODO: make this more efficient (not brute force)
        for i in 0..self.prime {
            let inv = FieldElement::new(i, P);
            let out = inv * other;
            if out == FieldElement::new(1, P) {
                return inv * self;
            }
        }

        panic!("No multiplicative inverse found");
    }
}

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

/// Generate a random u32 using openssl `rand_bytes`
fn rand_u32() -> u32 {
    let mut buf: [u8; 4] = [0; 4];
    rand_bytes(&mut buf).unwrap();

    let mut rand_val: u32 = 0;
    rand_val += (buf[0] as u32) << 0;
    rand_val += (buf[1] as u32) << 8;
    rand_val += (buf[2] as u32) << 16;
    rand_val += (buf[3] as u32) << 24;

    return rand_val;
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
