//! Implementation of the Shamir's Secret Sharing scheme.

use crate::field::Field;
use crate::field::Field;
use rand::thread_rng;
#[cfg(feature = "parse")]
use regex::Regex;
use std::fmt::{Debug, Display};

/// Trait to obtain the x coordinate of a share.
pub trait GetX<X: Copy> {
    /// Returns the x coordinate of a share.
    fn getx(self) -> X;
}

/// Trait for types implementing Shamir's Secret Sharing.
pub trait Shamir<F: Field> {
    /// Type for the x coordinate of shares.
    type X: Copy + From<u8>;
    /// Type for shares split from the secret.
    type Share: Copy + Debug + PartialEq + GetX<Self::X>;

    /// Splits a secret into n shares, with k shares being sufficient to reconstruct it.
    fn split(secret: &F, k: usize, n: usize) -> Vec<Self::Share>;
}

/// Instance of `Shamir` using compact shares.
pub struct CompactShamir;
/// Instance of `Shamir` using randomized shares.
pub struct RandomShamir;

/// Representation of a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share<X, Y> {
    x: X,
    y: Y,
}

impl<X, Y> Display for Share<X, Y>
where
    X: Display,
    Y: Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{}|{}", self.x, self.y))
    }
}

impl<X: Copy, Y> GetX<X> for Share<X, Y> {
    fn getx(self) -> X {
        self.x
    }
}

type CompactShare<F> = Share<u8, F>;
type RandomShare<F> = Share<F, F>;

fn check_split_parameters(k: usize, n: usize) {
    debug_assert!(k != 0);
    debug_assert!(n != 0);
    debug_assert!(k <= n);
    debug_assert!(n < 256);
}

fn check_reconstruct_parameters<X, Y>(shares: &[Share<X, Y>], k: usize)
where
    X: Debug + PartialEq,
    Y: Debug,
{
    debug_assert!(k != 0);
    debug_assert!(k < 256);
    debug_assert!(shares.len() >= k);
    for (i, s) in shares.iter().enumerate() {
        for (j, t) in shares.iter().enumerate() {
            if i != j {
                debug_assert!(s.x != t.x);
            }
        }
    }
}

fn generate_polynom<F: Field + Debug + Display>(secret: &F, k: usize) -> Vec<F> {
    // random number generator
    let mut rng = thread_rng();

    let mut polynom = Vec::with_capacity(k);
    //println!("Polynom = {}", secret);
    for i in 1..k {
        polynom.push(F::uniform(&mut rng));
        //println!("    + {} x^{}", polynom.last().unwrap(), i);
    }

    polynom
}

impl<F: Field + Debug + Display> Shamir<F> for CompactShamir {
    type X = u8;
    type Share = CompactShare<F>;

    fn split(secret: &F, k: usize, n: usize) -> Vec<Self::Share> {
        check_split_parameters(k, n);

        let polynom = generate_polynom(secret, k);

        let mut shares: Vec<Self::Share> = Vec::with_capacity(n);
        for i in 1..=(n as u8) {
            let x = F::from(i);

            let mut y = *secret;
            let mut xn = x;
            for p in &polynom {
                y += &(xn * p);
                xn = xn * &x;
            }

            shares.push(Self::Share { x: i, y })
        }

        shares
    }
    


}

impl<F: Field + Debug + Display> Shamir<F> for RandomShamir {
    type X = F;
    type Share = RandomShare<F>;

    fn split(secret: &F, k: usize, n: usize) -> Vec<Self::Share> {
        check_split_parameters(k, n);

        let polynom = generate_polynom(secret, k);
        let mut rng = thread_rng();

        let mut shares: Vec<Self::Share> = Vec::with_capacity(n);
        for _ in 0..n {
            let x = 'retry: loop {
                let x = F::uniform(&mut rng);
                if x == F::ZERO {
                    continue 'retry;
                }
                for s in &shares {
                    if x == s.x {
                        continue 'retry;
                    }
                }
                break x;
            };

            let mut y = *secret;
            let mut xn = x;
            for p in &polynom {
                y += &(xn * p);
                xn = xn * &x;
            }

            shares.push(Self::Share { x, y })
        }

        shares
    }
}


