extern crate rand;
extern crate secp256k1;
use rand::prelude::*;
use secp256k1::key::*;
fn generate_key<T>(ctx: &secp256k1::Secp256k1<T>) -> SecretKey {
    let alpha: [u8; 32] = random();
    SecretKey::from_slice(ctx, &alpha).unwrap()
}


fn receiver<T>(ctx: &secp256k1::Secp256k1<T>, choice: u8, s: PublicKey)
{
    // check s != G
    let x = generate_key();
    // compute H(S)
    let t =;
    let choice_key = [0u8;32];
    choice_key[31] = choice;
    let c = SecretKey::from_slice(ctx, &choice_key).unwrap();
    t.mul_assign(ctx, &c);
    t.add_exp_assign(ctx, &x);
    // Send Over t

    let mut H = hash::new();
    H.add(s);
    H.add(t);
    s.add_exp_assign(ctx, &x);
    H.add(s);

    let k = H.finalize();

    // recv msgs
    decrypt(m[choice], k);
}


fn sender<T>() {
    let y = generate_key();
    let t = ;
    // Get R

    let mut H = hash::new();
    H.add(y.pub());
    H.add(R);

    R.mul_assign(ctx, &y);

    t.mul_assign(ctx, &negate(ctx, &y));
    let t_acc = ZERO;

    for x in 0..256 {
        let Hh = H.clone();
        Hh.add(t_acc);
        Hh.finalize();
        // encrypt
        t_acc.add_assign(t);
    }
}

fn generate_factor_table<T>(ctx: &secp256k1::Secp256k1<T>) -> [SecretKey; 32] {
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
fn mul_by_256<T>(ctx: &secp256k1::Secp256k1<T>, s: &SecretKey) -> [SecretKey; 256] {
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

fn assign_add<T>(ctx: &secp256k1::Secp256k1<T>, s: &mut [SecretKey; 256], c: &SecretKey) {
    for a in s.iter_mut() {
        a.add_assign(ctx, c);
    }
}
use std::sync::Once;
static mut NEG_ONE: SecretKey = secp256k1::key::ONE_KEY;
static INIT: Once = Once::new();
fn negate<T>(ctx: &secp256k1::Secp256k1<T>, c: &SecretKey) -> SecretKey {
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








fn main() -> Result<(), secp256k1::Error> {
    let ctx = &secp256k1::Secp256k1::new();
    let factor_table = generate_factor_table(ctx);
    let alpha = generate_key(ctx);

    let mut alphas = mul_by_256(ctx, &alpha);


    let mut alphas_min_phi : [[SecretKey; 256]; 32] = [alphas; 32];
    let mut sigma_alpha = secp256k1::key::ZERO_KEY;
    {
        let mut count = 0;
        for row in alphas_min_phi.iter_mut() {
            let mut phi = generate_key(ctx);
            let neg_phi = negate(ctx, &phi);
            assign_add(ctx, row, &neg_phi);
            phi.mul_assign(ctx, &factor_table[count]);
            sigma_alpha.add_assign(ctx, &phi);
            count+=1;
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
    Ok(())
}
