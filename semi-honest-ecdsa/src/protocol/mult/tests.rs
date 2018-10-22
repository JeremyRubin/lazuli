use crate::protocol;
use crate::test::Bencher;
use crate::*;
use std::sync::mpsc::*;

use std::os::unix::net::UnixStream;
use std::thread;

fn verify_shares(
    a: scalars::scalar,
    b: scalars::scalar,
    mut s_a: scalars::scalar,
    s_b: scalars::scalar,
) {
    let ctx = &secp256k1::Secp256k1::new();
    let mut a =
        secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&a)).unwrap();
    let b = secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&b)).unwrap();
    crate::scalars::secp256k1_scalar_add_assign(&mut s_a, &s_b);
    let s_a =
        secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&s_a)).unwrap();
    a.mul_assign(ctx, &b);
    assert_eq!(a, s_a);
}
fn test_mult<S: 'static, R: 'static>(sender: S, receiver: R)
where
    S: Fn(&scalars::scalar, UnixStream) -> scalars::scalar,
    R: Fn(&scalars::scalar, &mut dyn ReadWrite) -> scalars::scalar,
    R: Send,
    S: Send,
{
    let (mut sock1, mut sock2) = UnixStream::pair().unwrap();
    let h2 = {
        thread::spawn(move || {
            let secret = crate::scalars::random_scalar();
            let share = sender(&secret, sock1);
            (secret, share)
        })
    };
    let h1 = {
        thread::spawn(move || {
            let secret = crate::scalars::random_scalar();
            let share = receiver(&secret, &mut sock2.try_clone().unwrap());
            (secret, share)
        })
    };

    let (mut a, mut s_a) = h1.join().unwrap();
    let (mut b, mut s_b) = h2.join().unwrap();
    verify_shares(a, b, s_a, s_b);
}

#[derive(Clone)]
struct Receiver<T>(T);
impl<T> Receiver<T>
where
    T: 'static,
    T: Send + Clone,
    T: Fn(&scalars::scalar, &mut dyn ReadWrite) -> scalars::scalar,
{
    fn call(&self, s: &scalars::scalar, r: &mut dyn ReadWrite) -> scalars::scalar {
        self.0(s, r)
    }
}

fn bench_setup<R: 'static>(receiver: Receiver<R>) -> UnixStream
where
    R: Send + Clone,
    R: Fn(&scalars::scalar, &mut dyn ReadWrite) -> scalars::scalar,
{
    let (mut sock1, mut sock2) = UnixStream::pair().unwrap();

    thread::spawn(move || {
        let secret = crate::scalars::random_scalar();
        let share = receiver.call(&secret, &mut sock2);
    });

    sock1
}
fn bench_mult<S: 'static, R: 'static>(sender: S, receiver: Receiver<R>, b: &mut Bencher)
where
    S: Fn(&scalars::scalar, UnixStream) -> scalars::scalar,
    R: Fn(&scalars::scalar, &mut dyn ReadWrite) -> scalars::scalar,
    R: Send + Sync + Clone,
    S: Send,
{
    b.iter(|| {
        let sock = bench_setup(receiver.clone());
        let secret = crate::scalars::random_scalar();
        let share = sender(&secret, sock);
    });
}

#[test]
fn mult_works() {
    test_mult(protocol::mult::sender::run, protocol::mult::receiver::run);
}

#[test]
fn scale_free() {
    test_mult(
        protocol::mult::sender::run_scale_free,
        protocol::mult::receiver::run_scale_free,
    );
}

#[bench]
fn bench_scaled_mult(b: &mut Bencher) {
    bench_mult(
        protocol::mult::sender::run,
        Receiver(protocol::mult::receiver::run),
        b,
    );
}

#[bench]
fn bench_scale_free_mult(b: &mut Bencher) {
    bench_mult(
        protocol::mult::sender::run_scale_free,
        Receiver(protocol::mult::receiver::run_scale_free),
        b,
    );
}
