
#![feature(test)]
extern crate test;
extern crate rand;
extern crate secp256k1;
extern crate sha2;
mod protocol;
mod util;
mod scalars;
use crate::util::*;
use rand::prelude::*;

fn main() -> Result<(), secp256k1::Error> {
    Ok(())

    /*{
        sigma_beta.add_assign(ctx, &sigma_alpha);

        beta.mul_assign(ctx, &alpha);

        assert_eq!(beta, sigma_beta);
    }*/
}
