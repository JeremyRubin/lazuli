use crate::*;
#[test]
fn test_2pc_sig() {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let m = scalars::random_scalar();
    std::thread::spawn(move || {
        protocol::ecdsa::twopc::run(&m, a);
    });
    protocol::ecdsa::twopc::run(&m, b);
}
