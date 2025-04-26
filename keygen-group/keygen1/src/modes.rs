use crate::cli::Cli;
use crate::utils::*;
use argon2::{Argon2, Params, Version, Algorithm};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha512;
use std::fs;

pub fn generate_argon2(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw = require_password(&cli.password);
    let mut filenames = vec![];

    for i in 1..=count {
        let seed = derive_argon2(&pw, &format!("salt{}", i), 32);
        let key = prng(&seed, size as usize);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_scrypt(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw = require_password(&cli.password);
    let mut filenames = vec![];

    for i in 1..=count {
        let mut seed = vec![0u8; 32];
        scrypt(
            pw.as_bytes(),
            format!("salt{}", i).as_bytes(),
            &ScryptParams::recommended(),
            &mut seed,
        )
        .unwrap();
        let key = prng(&seed, size as usize);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_pbkdf2(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw = require_password(&cli.password);
    let mut filenames = vec![];

    for i in 1..=count {
        let mut seed = vec![0u8; 32];
        pbkdf2_hmac::<Sha512>(
            pw.as_bytes(),
            format!("salt{}", i).as_bytes(),
            100_000,
            &mut seed,
        );
        let key = prng(&seed, size as usize);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_dualpass(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw1 = require_password(&cli.password);
    let pw2 = require_password(&cli.password2);
    let mut filenames = vec![];

    for i in 1..=count {
        let s1 = derive_argon2(&pw1, &format!("dp1-{}", i), 32);
        let mut s2 = vec![0u8; 32];
        pbkdf2_hmac::<Sha512>(
            pw2.as_bytes(),
            format!("dp2-{}", i).as_bytes(),
            100_000,
            &mut s2,
        );
        let seed = xor(&s1, &s2);
        let key = prng(&seed, size as usize);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_xor_prng(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw = require_password(&cli.password);
    let mut filenames = vec![];

    for i in 1..=count {
        let s1 = derive_argon2(&pw, &format!("xor1-{}", i), 32);
        let s2 = derive_argon2(&pw, &format!("xor2-{}", i), 32);
        let key1 = prng(&s1, size as usize);
        let key2 = prng(&s2, size as usize);
        let key = xor(&key1, &key2);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_random(_cli: &Cli, size: u64, count: u32) -> Vec<String> {
    fs::create_dir_all("r").unwrap();
    let mut filenames = vec![];

    for i in 1..=count {
        let mut key = vec![0u8; size as usize];
        ChaCha20Rng::from_rng(OsRng).unwrap().fill_bytes(&mut key);
        let filename = format!("r/{}.key", i);
        if std::path::Path::new(&filename).exists() {
            println!("Skipping: {} (already exists)", filename);
            continue;
        }
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

pub fn generate_multikey(cli: &Cli, size: u64, count: u32) -> Vec<String> {
    let pw = require_password(&cli.password);
    let mut filenames = vec![];

    for i in 1..=count {
        let salt = format!("multi-{}", i);
        let seed = derive_argon2(&pw, &salt, 32);
        let key = prng(&seed, size as usize);
        let filename = format!("{}.key", i);
        write_to_file(&filename, &key).unwrap();
        filenames.push(filename);
    }

    filenames
}

fn derive_argon2(pw: &str, salt: &str, size: usize) -> Vec<u8> {
    let params = Params::new(65536, 3, 1, None).unwrap();
    let mut seed = vec![0u8; size];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt.as_bytes(), &mut seed)
        .unwrap();
    seed
}
