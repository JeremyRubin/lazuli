use super::*;
use crate::protocol;
#[test]
fn OT() {
    let ctx = &secp256k1::Secp256k1::new();

    use std::os::unix::net::UnixStream;
    use std::thread;

    let (mut sock1, mut sock2) = UnixStream::pair().unwrap();
    let h2 = {
        let ctx = ctx.clone();
        thread::spawn(move || {
            let mut v = vec![[0u8; 32]; 256];
            for (i, m) in v.iter_mut().enumerate() {
                m[31] = i as u8;
            }
            for x in 0..=255 {
                protocol::ot::sender::run(
                    &ctx,
                    &mut v.clone().as_slice(),
                    crate::util::xor_cipher,
                    &mut sock2,
                );
            }
        })
    };
    let h1 = {
        let ctx = ctx.clone();
        thread::spawn(move || {
            let mut v_orig = [0u8; 32];
            for x in 0..=255 {
                let v = protocol::ot::receiver::run(
                    &ctx,
                    x,
                    crate::util::xor_decipher_scalar,
                    &mut sock1,
                );
                v_orig[31] = x;
                assert_eq!(v, crate::scalars::secp256k1_scalar_set_b32(&v_orig));
            }
        })
    };

    h1.join().unwrap();
    h2.join().unwrap();
}
