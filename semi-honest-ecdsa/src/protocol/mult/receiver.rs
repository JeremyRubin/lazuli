use crate::*;
use std::sync::mpsc::*;
use std::thread;
pub fn run<T: 'static>(beta: &scalars::scalar, peer: T) -> thread::JoinHandle<scalars::scalar>
where
    T: HasTryClone + ReadWrite + Send,
{
    let (tx, rx) = channel();
    let r = thread::spawn(move || {
        let mut sigma_beta = [0u64; 4];
        for (mut v, shift) in rx.iter().take(32).zip((0u8..32u8).rev()) {
            scalars::non_constant_time_shift(&mut v, shift);
            scalars::secp256k1_scalar_add_assign(&mut sigma_beta, &v);
        }
        sigma_beta
    });
    {
        let beta = beta.clone();
        let mut peer_clone = peer.try_clone();
        thread::spawn(move || {
            // MSB to LSB
            let ctx = &secp256k1::Secp256k1::new();
            for choice in scalars::bytes_from_scalar(&beta).iter() {
                tx.send(protocol::ot::receiver::run(
                    ctx,
                    *choice,
                    xor_decipher_scalar,
                    &mut peer_clone,
                ));
            }
        });
    }
    r
}

pub fn run_scale_free<T: 'static>(
    beta: &scalars::scalar,
    peer: T,
) -> thread::JoinHandle<scalars::scalar>
where
    T: ReadWrite + HasTryClone + Send,
{
    let (tx, rx) = channel();
    let r = thread::spawn(move || {
        let mut sigma_beta = [0u64; 4];
        for mut v in rx.iter().take(32) {
            scalars::secp256k1_scalar_add_assign(&mut sigma_beta, &v);
        }
        sigma_beta
    });
    // LSB to MSB
    {
        let beta = beta.clone();
        let mut peer_clone = peer.try_clone();
        thread::spawn(move || {
            let ctx = &secp256k1::Secp256k1::new();
            for choice in scalars::bytes_from_scalar(&beta).iter().rev() {
                tx.send(protocol::ot::receiver::run(
                    ctx,
                    *choice,
                    xor_decipher_scalar,
                    &mut peer_clone,
                ));
            }
        });
    }
    r
}
