extern crate rand;
extern crate secp256k1;
extern crate sha2;
mod protocol;
mod util;
use crate::util::*;
use rand::prelude::*;

fn main() -> Result<(), secp256k1::Error> {
    let ctx = &secp256k1::Secp256k1::new();
    let factor_table = generate_factor_table(ctx);
    let alpha = generate_key(ctx);

    let mut alphas = mul_by_256(ctx, &alpha);

    let mut alphas_min_phi: [[SecretKey; 256]; 32] = [alphas; 32];
    let mut sigma_alpha = secp256k1::key::ZERO_KEY;
    {
        let mut count = 0;
        for row in alphas_min_phi.iter_mut() {
            let mut phi = generate_key(ctx);
            let neg_phi = negate(ctx, &phi);
            assign_add(ctx, row, &neg_phi);
            phi.mul_assign(ctx, &factor_table[count]);
            sigma_alpha.add_assign(ctx, &phi);
            count += 1;
        }
    }

    let mut sigma_beta = secp256k1::key::ZERO_KEY;
    let bs: [u8; 32] = random();
    let mut beta = SecretKey::from_slice(ctx, &bs)?;
    let mut count = 0;
    for (elt, row) in bs.iter().rev().zip(alphas_min_phi.iter_mut()) {
        row[*elt as usize].mul_assign(ctx, &factor_table[count]);
        sigma_beta.add_assign(ctx, &row[*elt as usize]);
        count += 1;
    }

    {
        sigma_beta.add_assign(ctx, &sigma_alpha);

        beta.mul_assign(ctx, &alpha);

        assert_eq!(beta, sigma_beta);
    }

    use std::os::unix::net::UnixStream;
    use std::thread;

    let (mut sock1, mut sock2) = UnixStream::pair().unwrap();
    let h1 = {
        let ctx = ctx.clone();
        thread::spawn(move || {
            protocol::receiver::run(&ctx, 5, &mut sock1)
        })
    };

    let mut v = Vec::new();
    for x in 0..256 {
        v.push([0u8;32]);
        v[x][31] = x as u8;
    }
    let v5_orig = v[5];
    let h2 = {
        let ctx = ctx.clone();
        thread::spawn(move || {
            protocol::sender::run(&ctx, &mut v, &mut sock2);
        })
    };

    let v5 = h1.join().unwrap();
    h2.join();

    assert_eq!(v5, v5_orig);
    Ok(())
}
