#![feature(asm)]
#![feature(test)]
extern crate rand;
extern crate secp256k1;
extern crate sha2;
extern crate test;
mod protocol;
mod scalars;
mod util;
use crate::util::*;
use rand::prelude::*;

fn main() -> Result<(), secp256k1::Error> {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    std::thread::spawn(|| {
        protocol::ecdsa::twopc::run(&[1, 2, 3, 4], a);
    });
    protocol::ecdsa::twopc::run(&[1, 2, 3, 4], b);
    Ok(())

    // Structure:
    // Pick Privkeys
    // Plaintext Pick Pubkeys
    // Pick Message
    // Pick Nonces
    // Share Nonces to generate r = kG.x
    // Generate Inverse Nonces
    // Start thread for key shares M*leader + r*a to be sender.
    // Start thread for nonce inverse shares q
    //
    // Order Synchronization:
    //     Each Nonce Inverse Share shall be on listener status, multiplying for any inbound
    //     request. Each nonce inverse share has an index.
    //
    //     Each Key share connects to the i-th nonce share (except their own...) and
    //     initiates a multiplication.
    //     The Multiplication immediately returns, because it's value is independent of
    //     the result the counterparty learns.
    //
    //      When the i-th share is multiplying with the i-th nonce, we optimize it to
    //      multiply directly. However, before proceeding with this result, we must complete
    //      all n-1 multiplications and sum the result. When finished, we proceed to request
    //      multiplication by the i+1st nonce.
    //
    //      With this execution, there are O(n-1) multiplications done where the node
    //      picks the result arbitrarily and O(n-1) multiplications (in parallel) where
    //      the result is non-arbitrary. Therefore, the total latency required to compute
    //      is O(n).
    //
    //      The number of simultaneously opened sockets is also n-1
    //
    //
    //
    //
    //      If computing many signatures simultaneously (e.g., for a tree of presigneds)
    //      then the recurrence below governs the _total number_ of threads _created_.
    //      These threads _may_ be created at the same time, or may occur in various orders,
    //      implying a shared semaphore may be used to limit the max concurrency.
    //
    //      T(N) = 2*T(N/2) + (N-1)^2 = O(2N^2)
    //
    //      Because there are N workers doing equal work, the total is:
    //
    //      O(2N)
    //
    //      Another way to see this recurrence is that there are log N signatures each node must
    //      participate in in the tree, and subsequent one has half the participants, starting with
    //      N, so the total per participant is O(2N).
    //
    //
    //
    /*{
        sigma_beta.add_assign(ctx, &sigma_alpha);
    
        beta.mul_assign(ctx, &alpha);
    
        assert_eq!(beta, sigma_beta);
    }*/}
