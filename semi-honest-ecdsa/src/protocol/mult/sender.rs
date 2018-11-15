use crate::*;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
pub fn run<T: 'static>(
    alpha: &scalars::scalar,
    peer: T,
) -> (scalars::scalar, thread::JoinHandle<()>)
where
    T: ReadWrite + HasTryClone + Send,
{
    let mut neg_sigma_alpha = [0u64; 4];
    let t = {
        // MSB to LSB
        let (tx, rx) = channel::<[[u64; 4]; 256]>();
        let t = {
            let mut peer_clone = peer.try_clone();
            thread::spawn(move || {
                let ctx = &secp256k1::Secp256k1::new();
                for mut row in rx.iter().take(32) {
                    protocol::ot::sender::run(&ctx, &mut row[..], xor_cipher, &mut peer_clone);
                }
            })
        };
        let mut alphas: [[u64; 4]; 256] = scalars::scalar_mul_by_256(&alpha);
        for count in (0..32).rev() {
            let mut neg_phi = scalars::random_scalar();
            let mut row = alphas.clone();
            scalars::assign_add(&mut row, &neg_phi);
            tx.send(row);
            scalars::non_constant_time_shift(&mut neg_phi, count as u8);
            scalars::secp256k1_scalar_add_assign(&mut neg_sigma_alpha, &neg_phi);
        }
        t
    };

    scalars::secp256k1_scalar_negate(&mut neg_sigma_alpha);
    (neg_sigma_alpha, t)
}

pub fn run_scale_free<T: 'static>(
    alpha: &scalars::scalar,
    peer: T,
) -> (scalars::scalar, thread::JoinHandle<()>)
where
    T: ReadWrite + HasTryClone + Send,
{
    let mut neg_sigma_alpha = [0u64; 4];
    let t = {
        // MSB to LSB
        let (tx, rx) = channel::<[[u64; 4]; 256]>();
        let t = {
            let mut peer_clone = peer.try_clone();
            thread::spawn(move || {
                let ctx = &secp256k1::Secp256k1::new();
                for mut row in rx.iter().take(32) {
                    protocol::ot::sender::run(&ctx, &mut row[..], xor_cipher, &mut peer_clone);
                }
            })
        };
        let mut alpha_doubles = alpha.clone();
        for count in (0..32) {
            scalars::non_constant_time_shift(&mut alpha_doubles, (count > 0) as u8);
            let mut row: [[u64; 4]; 256] = scalars::scalar_mul_by_256(&alpha_doubles);
            let mut neg_phi = scalars::random_scalar();
            scalars::assign_add(&mut row, &neg_phi);
            tx.send(row);
            scalars::secp256k1_scalar_add_assign(&mut neg_sigma_alpha, &neg_phi);
        }
        t
    };

    scalars::secp256k1_scalar_negate(&mut neg_sigma_alpha);
    (neg_sigma_alpha, t)
}

pub fn run_scale_free_stupid_parallel<T: 'static>(
    peer: T,
) -> (Sender<scalars::scalar>, scalars::scalar, thread::JoinHandle<()>)
where
    T: ReadWrite + HasTryClone + Send,
{
    let (tx_alpha, rx_alpha) = channel::<scalars::scalar>();
    let mut neg_phis = std::sync::Arc::<[[u64; 4];32]>::new([[0u64;4];32]);
    // There are no copies yet, so we can just make_mut to get a mutable ref
    for neg_phi in std::sync::Arc::make_mut(&mut neg_phis).iter_mut() {
        *neg_phi = scalars::random_scalar();
    }
    let t = {
        // MSB to LSB
        let (tx_row, rx_row) = channel::<[[u64; 4]; 256]>();
        let t = {
            let mut peer_clone = peer.try_clone();
            thread::spawn(move || {
                let ctx = &secp256k1::Secp256k1::new();
                for mut row in rx_row.iter().take(32) {
                    protocol::ot::sender::run(&ctx, &mut row[..], xor_cipher, &mut peer_clone);
                }
            })
        };
        // Now we increment the reference count via clone and pass to the worker thread
        let neg_phis = std::sync::Arc::clone(&neg_phis);
        thread::spawn(move || -> Option<()> {
            let mut alpha : scalars::scalar = rx_alpha.recv().ok()?;
            for (count, neg_phi) in neg_phis.iter().take(32).enumerate() {
                scalars::non_constant_time_shift(&mut alpha, (count > 0) as u8);
                let mut row = scalars::scalar_mul_by_256(&alpha);
                scalars::assign_add(&mut row, &neg_phi);
                tx_row.send(row).ok()?;
            }
            Some(())
        });
        t
    };
    

    // Sum up and return
    let mut neg_sigma_alpha = neg_phis[0];
    for neg_phi in neg_phis.iter().skip(1) {
        scalars::secp256k1_scalar_add_assign(&mut neg_sigma_alpha, &neg_phi);
    }
    scalars::secp256k1_scalar_negate(&mut neg_sigma_alpha);
    (tx_alpha, neg_sigma_alpha, t)
}
