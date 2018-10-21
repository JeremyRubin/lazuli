use crate::scalars;
use rand::prelude::*;
pub use secp256k1::key::*;
pub use sha2::{Digest, Sha256};

use std::io::*;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
pub trait HasTryClone {
    fn try_clone(&self) -> Self;
}
impl HasTryClone for UnixStream {
    fn try_clone(&self) -> Self {
        self.try_clone().unwrap()
    }
}
pub trait ReadWrite: Read + Write + Send {}
impl ReadWrite for TcpStream {}
impl ReadWrite for UnixStream {}
use secp256k1::key::*;
pub fn generate_key<T>(ctx: &secp256k1::Secp256k1<T>) -> SecretKey {
    let alpha: [u8; 32] = random();
    SecretKey::from_slice(ctx, &alpha).unwrap()
}

/// The Oracle Function Hashes a Curve Point and then finds the next valid
/// curve point from that hash.
///
pub fn oracle<T>(ctx: &secp256k1::Secp256k1<T>, s: &PublicKey) -> PublicKey {
    // TODO: Is it safe to always pick 2?
    let mut t = [0x02u8; 33];
    for (w, b) in t.iter_mut().skip(1).zip(
        Sha256::new()
            .chain(b"ImplementationObliviousTransfers")
            .chain(&s.serialize()[0..])
            .result()
            .iter(),
    ) {
        *w = *b;
    }
    for x in 0..=255 {
        // TODO: Is this cryptographically guaranteed to terminate?
        match PublicKey::from_slice(ctx, &t) {
            Ok(x) => return x,
            Err(_) => {
                t[32] = t[32].wrapping_add(1);
            }
        }
    }
    panic!("numbers broke");
}

// The Factor Table is a somewhat annoying to generate table which only needs
// to be generated one time which represents the factors needed to be multiplied
// by for each blinding term learned.
pub fn generate_factor_table<T>(ctx: &secp256k1::Secp256k1<T>) -> [scalars::scalar; 32] {
    let mut x = [ZERO_KEY; 32];
    let mut scalars = [[0u64; 4]; 32];
    let mut base = 1u64;
    for i in 0..=7 {
        scalars[i][0] = base;
        scalars[i + 8][1] = base;
        scalars[i + 18][2] = base;
        scalars[i + 24][3] = base;
        base *= 256;
    }
    scalars
}

use std::mem;
/// mul_by_256 takes a Secret Key and efficiently (by repeated adding)
/// generates a table of every n*sk for n in [0,256)
pub fn mul_by_256<T>(ctx: &secp256k1::Secp256k1<T>, s: &SecretKey) -> [SecretKey; 256] {
    let mut x: [SecretKey; 256];
    unsafe {
        x = mem::uninitialized();
        x[0] = secp256k1::key::ZERO_KEY;
        for i in 1..=255 {
            x[i] = x[i - 1].clone();
            x[i].add_assign(ctx, s);
        }
    }
    x
}

/// assign_add adds a constant secret key c to every element of a set of 256
/// keys s.
pub fn assign_add<T>(ctx: &secp256k1::Secp256k1<T>, s: &mut [SecretKey; 256], c: &SecretKey) {
    for a in s.iter_mut() {
        a.add_assign(ctx, c);
    }
}
/// The Constant NEG_ONE is CURVE_ORDER with byte 31 -1
pub const NEG_ONE: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 64,
];

/// negate multiplies by -1.
pub fn negate<T>(ctx: &secp256k1::Secp256k1<T>, c: &SecretKey) -> SecretKey {
    let mut n = c.clone();
    n.mul_assign(ctx, &SecretKey::from_slice(ctx, &NEG_ONE).unwrap());
    n
}

// xor_cipher does what it sounds like
pub fn xor_cipher<M>(m: &M, key: &[u8], r: &mut dyn ReadWrite)
where
    M: ByteViewable,
{
    assert_eq!(key.len(), 32);
    let mut x = [0u8; 32];
    for (idx, (byte, k)) in m.view().as_ref().iter().zip(key.iter()).enumerate() {
        x[idx] = (*byte ^ k);
    }
    r.write_all(&x[..]);
}
pub fn xor_decipher_scalar(key: &[u8], r: &[u8]) -> scalars::scalar {
    assert_eq!(key.len(), 32);
    assert_eq!(r.len(), 32);
    let mut m = [0u8; 32];
    for (w, (byte, k)) in m.iter_mut().zip(r.iter().zip(key.iter())) {
        *w = *byte ^ k;
    }
    scalars::secp256k1_scalar_set_b32(&m)
}

pub trait ByteViewable {
    type T: AsRef<[u8]>;
    fn view(&self) -> Self::T;
}
impl ByteViewable for [u64; 4] {
    type T = [u8; 32];
    fn view(&self) -> [u8; 32] {
        scalars::bytes_from_scalar(self)
    }
}

impl ByteViewable for [u8; 32] {
    type T = [u8; 32];
    fn view(&self) -> [u8; 32] {
        *self
    }
}
