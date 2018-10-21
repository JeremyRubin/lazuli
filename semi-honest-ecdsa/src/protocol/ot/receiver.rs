use crate::util::*;
mod protocol {
    use super::*;
    pub mod start {
        use super::*;
        pub struct start<'a>(&'a mut dyn ReadWrite);
        pub struct started<'a>(&'a mut dyn ReadWrite);
        impl<'a> start<'a> {
            pub fn new(a: &'a mut dyn ReadWrite) -> start<'a> {
                start(a)
            }
            pub fn next(self) -> started<'a> {
                started(self.0)
            }
        }
        impl<'a> started<'a> {
            pub fn get_stream<'b>(a: super::get_s::get_s<'a, 'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }
    pub mod get_s {
        use super::*;
        pub struct get_s<'a, 'b>(pub &'b mut super::start::started<'a>);
        pub struct got_s<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> get_s<'a, 'b> {
            pub fn next<C>(self, ctx: &secp256k1::Secp256k1<C>) -> (PublicKey, got_s<'b>)
            where
                C: secp256k1::Signing,
            {
                let r: &'b mut dyn ReadWrite = super::start::started::get_stream(self);
                let mut buffer = [0u8; 33];
                match r.read_exact(&mut buffer) {
                    Ok(_) => (),
                    Err(a) => panic!("receiver reading S failed with {:?}", a),
                };
                match PublicKey::from_slice(ctx, &buffer) {
                    Ok(s) => (s, got_s(r)),
                    Err(e) => panic!("receiver taking S value failed with {:?}", e),
                }
            }
        }

        impl<'a> got_s<'a> {
            pub fn get_stream<'b>(a: super::send_r::send_r<'a, 'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }

    pub mod send_r {
        use super::*;
        pub struct send_r<'a, 'b>(pub &'b mut super::get_s::got_s<'a>);
        pub struct sent_r<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> send_r<'a, 'b> {
            pub fn next(self, r: &PublicKey) -> sent_r<'b> {
                let w: &'b mut dyn ReadWrite = super::get_s::got_s::get_stream(self);
                let b: [u8; 33] = r.serialize();
                w.write_all(&b).unwrap();
                w.flush();
                sent_r(w)
            }
        }

        impl<'a> sent_r<'a> {
            pub fn get_stream<'b>(a: super::get_es::get_es<'a, 'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }

    pub mod get_es {
        use super::*;
        pub struct get_es<'a, 'b>(pub &'b mut super::send_r::sent_r<'a>);
        pub struct got_ciphertext(pub Vec<u8>);
        impl<'a, 'b> get_es<'a, 'b> {
            pub fn next<C>(self, ctx: &secp256k1::Secp256k1<C>, choice: u8) -> got_ciphertext {
                let r: &'b mut dyn ReadWrite = super::send_r::sent_r::get_stream(self);
                // MUST BE CONSTANT TIME
/*
		{
			peer.read_exact(&mut unsafe{std::mem::transmute::<[[u64;4];256], [u8; 8192]>(row)}[..]);
			for r in row.iter_mut() {
				for v in r.iter_mut() {
					*v = v.from_be();
				}
			}
		} */

                let mut results = Vec::with_capacity(256);
                for t in 0..256 {
                    let mut buffer = vec![0u8; 32];
                    match r.read_exact(buffer.as_mut_slice()) {
                        Ok(_) => (),
                        Err(a) => panic!("read_exact failed in receiver get_es with {:?}", a),
                    }
                    results.push(buffer);
                }

                let mut ret = got_ciphertext(Vec::new());
                std::mem::swap(&mut ret.0, &mut results[choice as usize]);
                ret
            }
        }
    }
}

pub fn run<T, M, D>(
    ctx: &secp256k1::Secp256k1<T>,
    choice: u8,
    decrypt: D,
    peer: &mut dyn ReadWrite,
) -> M
where
    T: secp256k1::Verification + secp256k1::Signing,
    D: Fn(&[u8], &[u8]) -> M,
{
    let protocol = protocol::start::start::new(peer);
    let x = generate_key(ctx);
    let mut started = protocol.next();
    let (mut s, mut got_s) = protocol::get_s::get_s(&mut started).next(ctx);
    // check s != G
    assert_ne!(PublicKey::from_secret_key(ctx, &ONE_KEY), s);

    // compute H(S)
    let mut t = oracle(ctx, &s);
    let mut choice_key = [0u8; 32];
    choice_key[31] = choice;
    //TODO: Non Constnant time hell
    match SecretKey::from_slice(ctx, &choice_key) {
        Ok(c) => {
            t.mul_assign(ctx, &c);
            t.add_exp_assign(ctx, &x);
        }
        Err(k) => {
            t = PublicKey::from_secret_key(ctx, &x);
        }
    };
    // Send Over R = t
    let mut sent_r = protocol::send_r::send_r(&mut got_s).next(&t);

    let mut h = Sha256::new()
        .chain(&s.serialize()[0..])
        .chain(&t.serialize()[0..]);
    s.mul_assign(ctx, &x);
    let k = h.chain(&s.serialize()[0..]).result();

    // recv msg
    decrypt(
        k.as_slice(),
        &protocol::get_es::get_es(&mut sent_r).next(ctx, choice).0,
    )
}
