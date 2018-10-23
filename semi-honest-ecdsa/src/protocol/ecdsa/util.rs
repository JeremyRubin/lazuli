use std::thread::{spawn, JoinHandle};
pub type Inverse = (crate::scalars::scalar, JoinHandle<crate::scalars::scalar>);
pub fn background_inverse() -> Inverse {
    let nonce = crate::scalars::random_scalar();
    {
        let nonce_c = nonce.clone();
        (
            nonce,
            spawn(move || crate::scalars::secp256k1_scalar_inverse(&nonce_c)),
        )
    }
}

use std::sync::mpsc::{sync_channel, Receiver};

pub fn background_inverse_service(n: usize) -> Receiver<Inverse> {
    let (sender, receiver) = sync_channel(n);
    spawn(move || -> Option<()> {
        // Loops until receiver closed
        loop {
            sender.send(background_inverse()).ok()?
        }
    });
    receiver
}
