use super::*;
use crate::protocol;
#[test]
fn mult_works() {
    use std::os::unix::net::UnixStream;
    use std::thread;

    let (mut sock1, mut sock2) = UnixStream::pair().unwrap();
    let h2 = {
        thread::spawn(move || {
            let secret = [5, 4, 3, 2];
            let share = protocol::mult::sender::run(secret, sock1.try_clone().unwrap());
            (secret, share)
        })
    };
    let h1 = {
        thread::spawn(move || {
            let secret = [2, 0, 0, 0];
            let share = protocol::mult::receiver::run(&secret, &mut sock2);
            (secret, share)
        })
    };

    let (a, mut s_a) = h1.join().unwrap();
    let (b, s_b) = h2.join().unwrap();
    let ctx = &secp256k1::Secp256k1::new();
    let mut a =
        secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&a)).unwrap();
    let b = secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&b)).unwrap();
    println!("secrets, {:?}, {:?}", s_a, s_b);
    crate::scalars::secp256k1_scalar_add_assign(&mut s_a, &s_b);
    let s_a =
        secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&s_a)).unwrap();
    a.mul_assign(ctx, &b);
    assert_eq!(a, s_a);
}
