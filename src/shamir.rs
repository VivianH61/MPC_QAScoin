//! Implementation of the Shamir's Secret Sharing scheme.
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

    /// Reconstructs a secret from a set of shares, given the threshold parameter k. Returns `None`
    /// if reconstruction failed.
    fn reconstruct(shares: &[Self::Share], k: usize) -> Option<F>;

    /// Parses a share's x coordinate from a string. Returns `None` if the parsing fails.
    #[cfg(feature = "parse")]
    fn parse_x(s: &str) -> Option<Self::X>;
    /// Parses a share from a string. Returns `None` if the parsing fails.
    #[cfg(feature = "parse")]
    fn parse_share(s: &str) -> Option<Self::Share>;
}

/// Instance of `Shamir` using compact shares.
pub struct CompactShamir;

/// Share: A coordinate on the polynimia, (x, y).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share<X, Y> {
    x: X,
    y: Y,
}

// customize the output appearance
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

fn check_split_parameters(k: usize, n: usize) {
    debug_assert!(k != 0);
    debug_assert!(n != 0);
    debug_assert!(k <= n);
    debug_assert!(n < 256);
}

fn generate_polynom<F: Field + Debug + Display>(secret: &F, k: usize) -> Vec<F> {
    let mut rng = thread_rng();

    let mut polynom = Vec::with_capacity(k);
    println!("Polynom = {}", secret);
    for i in 1..k {
        polynom.push(F::uniform(&mut rng));
        println!("    + {} x^{}", polynom.last().unwrap(), i);
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

    fn reconstruct(shares: &[Self::Share], k: usize) -> Option<F> {
        let gfx: Vec<F> = shares.iter().map(|share| F::from(share.x)).collect();

        let mut secret = F::ZERO;
        for (i, si) in shares.iter().take(k).enumerate() {
            let mut lagrange = F::ONE;
            let mut denom = F::ONE;
            let xi = si.x;
            for (j, sj) in shares.iter().take(k).enumerate() {
                if j != i {
                    let xj = sj.x;
                    lagrange = lagrange * &gfx[j];
                    denom = denom * &F::from_diff(xj, xi);
                }
            }
            secret += &(lagrange * &si.y * &denom.invert());
        }
        Some(secret)
    }

    #[cfg(feature = "parse")]
    fn parse_x(s: &str) -> Option<Self::X> {
        s.parse::<u8>().ok()
    }

    #[cfg(feature = "parse")]
    fn parse_share(s: &str) -> Option<Self::Share> {
        let regex = Regex::new(r"^([0-9]+)\|([0-9a-fA-F]+)$").unwrap();
        let captures = regex.captures(s)?;

        let x: u8 = captures[1].parse().ok()?;
        let y = F::from_bytes(&hex::decode(&captures[2]).ok()?)?;

        Some(Self::Share { x, y })
    }
}