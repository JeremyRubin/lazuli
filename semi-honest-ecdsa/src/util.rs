
use rand::prelude::*;
pub use secp256k1::key::*;
pub use sha2::{Digest, Sha256};

use std::io::*;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
pub trait ReadWrite : Read + Write {}
impl ReadWrite for TcpStream{}
impl ReadWrite for UnixStream{}
use secp256k1::key::*;
pub fn generate_key<T>(ctx: &secp256k1::Secp256k1<T>) -> SecretKey {
    let alpha: [u8; 32] = random();
    SecretKey::from_slice(ctx, &alpha).unwrap()
}


pub fn oracle<T>(ctx: &secp256k1::Secp256k1<T>, s: &PublicKey) -> PublicKey {
    // TODO: Is it safe to always pick 2?
    let mut t = [0x02u8;33];
    for (w, b) in t.iter_mut().skip(1).zip(Sha256::new().chain(&s.serialize()[0..]).result().iter()) {
        *w = *b;
    }
    loop {
        // TODO: Is this cryptographically guaranteed to terminate?
        match PublicKey::from_slice(ctx, &t) {
            Ok(x) => return x,
            Err(_) => {
                t[32] +=1; 
            }
        }
    }
    
}



pub fn generate_factor_table<T>(ctx: &secp256k1::Secp256k1<T>) -> [SecretKey; 32] {
    let mut twofivesix = [0u8;32];
    twofivesix[30] = 1;
    let tfs = SecretKey::from_slice(ctx, &twofivesix).unwrap();
    let mut x: [SecretKey; 32];
    unsafe {
        x = mem::uninitialized();
        x[0] = secp256k1::key::ONE_KEY;
        x[1] = tfs;
        for i in 2..32 {
            x[i] = x[i - 1].clone();
            x[i].mul_assign(ctx, &tfs);
        }
    }
    x
}

use std::mem;
pub fn mul_by_256<T>(ctx: &secp256k1::Secp256k1<T>, s: &SecretKey) -> [SecretKey; 256] {
    let mut x: [SecretKey; 256];
    unsafe {
        x = mem::uninitialized();
        x[0] = secp256k1::key::ZERO_KEY;
        for i in 1..256 {
            x[i] = x[i - 1].clone();
            x[i].add_assign(ctx, s);
        }
    }
    x
}

pub fn assign_add<T>(ctx: &secp256k1::Secp256k1<T>, s: &mut [SecretKey; 256], c: &SecretKey) {
    for a in s.iter_mut() {
        a.add_assign(ctx, c);
    }
}
use std::sync::Once;
static mut NEG_ONE: SecretKey = secp256k1::key::ONE_KEY;
static INIT: Once = Once::new();
pub fn negate<T>(ctx: &secp256k1::Secp256k1<T>, c: &SecretKey) -> SecretKey {
    INIT.call_once(|| {
        let mut minus_1 = secp256k1::constants::CURVE_ORDER;
        minus_1[31] -= 1;
        unsafe {
            NEG_ONE = SecretKey::from_slice(ctx, &minus_1).unwrap();
        }
    });
    let mut n = c.clone();
    n.mul_assign(ctx, unsafe { &NEG_ONE });
    n
}



pub fn cipher(m : &mut [u8;32], key : &[u8]) {
    assert_eq!(key.len(), 32);
    for (byte, k) in m.iter_mut().zip(key.iter()) {
        *byte ^= k;
    }
}


