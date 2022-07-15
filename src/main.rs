// use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use sss::field::Field;
use sss::gf2n::{GF256};
use sss::shamir::{CompactShamir, Shamir};
// use rand::thread_rng;
use regex::Regex;
use std::fmt::{Debug, Display};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};


fn main() {
    // shares should be in the range of [1, 255]
    let shares = 10;
    // threshold should be in the range of [1, shares]
    let threshold = 3;

    // split
    let secret_file = "privateKey.txt";
    split::<GF256, CompactShamir>(&secret_file, threshold, shares);
    // reconstruct
    let shares_file = "shares.txt";
    //reconstruct::<GF256, CompactShamir>(&shares_file, threshold);
}


fn split<F: Field + Debug + Display, S: Shamir<F>>(filename: &str, k: usize, n: usize)
where
    S::Share: Display,
{
    let secret = parse_secret::<F>(filename);
    println!("Secret = {}", secret);

    let shares = S::split(&secret, k, n);
    println!("Shares:");
    for s in &shares {
        println!("{}", s);
    }
}

fn reconstruct<F: Field + Debug + Display, S: Shamir<F>>(filename: &str, k: usize)
where
    S::Share: Display,
{
    let shares = parse_shares::<F, S>(filename);
    println!("Shares:");
    for s in &shares {
        println!("{}", s);
    }

    assert!(
        shares.len() >= k,
        "Found fewer shares than the threshold, cannot reconstruct!"
    );

    let secret = S::reconstruct(&shares, k);
    match secret {
        Some(s) => println!("Secret = {}", s),
        None => println!("Could not reconstruct the secret..."),
    }
}

// read the secret from a file for split
fn parse_secret<F: Field>(filename: &str) -> F {
    let mut file = File::open(filename).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let regex = Regex::new(r"^([0-9a-fA-F]+)\n?$").unwrap();
    let captures = match regex.captures(&contents) {
        Some(cap) => cap,
        None => panic!("Secret file must contains hexadecimal characters only",),
    };
    let bytes = match hex::decode(&captures[1]) {
        Ok(bytes) => bytes,
        Err(e) => panic!(
            "Couldn't parse secret file as hexadecimal characters: {}",
            e
        ),
    };
    match F::from_bytes(bytes.as_slice()) {
        Some(f) => f,
        None => panic!("Secret is not a valid represetation of a field element"),
    }
}

// read shares from a file for reconstruct
fn parse_shares<F: Field + Debug + Display, S: Shamir<F>>(filename: &str) -> Vec<S::Share> {
    let file = File::open(filename).unwrap();
    BufReader::new(file)
        .lines()
        .map(|line| S::parse_share(&line.unwrap()).unwrap())
        .collect()
}