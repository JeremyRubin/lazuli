use crate::*;

use crate::test::Bencher;
fn test_2pc_sig() {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let m = scalars::random_scalar();
    std::thread::spawn(move || {
        protocol::ecdsa::twopc::run(super::util::background_inverse, &m, a);
    });
    assert!(protocol::ecdsa::twopc::run(super::util::background_inverse, &m, b).is_some());
}
#[test]
fn do_test() {
    test_2pc_sig();
}

fn test_2pc_sig_inv(inv1: super::util::Inverse, inv2: super::util::Inverse) {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let m = scalars::random_scalar();
    std::thread::spawn(move || {
        protocol::ecdsa::twopc::run(|| inv1, &m, a);
    });
    assert!(protocol::ecdsa::twopc::run(|| inv2, &m, b).is_some());
}
#[bench]
fn do_bench(b: &mut Bencher) {
    let bg_inv = super::util::background_inverse_service(100);
    std::thread::sleep(std::time::Duration::from_secs(3));
    b.iter(|| {
        let inv1 = bg_inv.iter().next().unwrap();
        let inv2 = bg_inv.iter().next().unwrap();

        test_2pc_sig_inv(inv1, inv2)
    });
}
