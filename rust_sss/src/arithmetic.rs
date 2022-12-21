use openssl::rand::rand_bytes;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub};

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

#[derive(Debug, Copy, Clone)]
pub struct SecretShare {
    pub x: FieldElement,
    pub y: FieldElement,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct FieldElement {
    pub value: u32,
    pub prime: u32,
}

impl FieldElement {
    pub fn new(value: u32, prime: u32) -> FieldElement {
        // TODO: add Result for non prime numbers and values greater than prime
        return FieldElement {
            value: value % prime, // TODO: fix this hack: do not permit values larger than the prime
            prime,
        };
    }

    pub fn rand(prime: u32) -> FieldElement {
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
            let inv = FieldElement::new(i, self.prime);
            let out = inv * other;
            if out == FieldElement::new(1, self.prime) {
                return inv * self;
            }
        }

        panic!("No multiplicative inverse found");
    }
}
