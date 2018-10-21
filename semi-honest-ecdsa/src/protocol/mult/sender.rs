use crate::*;
use std::sync::mpsc::channel;
use std::thread;
pub fn run<T: 'static>(alpha: scalars::scalar, peer: T) -> scalars::scalar
where
    T: ReadWrite + HasTryClone + Send,
{
    let ctx = &secp256k1::Secp256k1::new();
    let mut alphas: [[u64; 4]; 256] = scalars::scalar_mul_by_256(&alpha);

    let mut neg_sigma_alpha = [0u64; 4];
    {
        // MSB to LSB
        let (tx, rx) = channel::<[[u64; 4]; 256]>();
        {
            let mut peer_clone = peer.try_clone();
            let ctx = ctx.clone();
            thread::spawn(move || {
                for mut row in rx.iter().take(32) {
                    protocol::ot::sender::run(&ctx, &mut row[..], xor_cipher, &mut peer_clone);
                }
            });
        }
        for count in (0..32).rev() {
            let mut neg_phi = scalars::random_scalar();
            let mut row = alphas.clone();
            scalars::assign_add(&mut row, &neg_phi);
            tx.send(row);
            scalars::non_constant_time_shift(&mut neg_phi, count as u8);
            scalars::secp256k1_scalar_add_assign(&mut neg_sigma_alpha, &neg_phi);
        }
    }

    scalars::secp256k1_scalar_negate(&mut neg_sigma_alpha);
    neg_sigma_alpha
}
