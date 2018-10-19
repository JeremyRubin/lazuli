
use crate::util::*;
mod protocol {
    use super::*;
    pub mod start {
        use super::*;
        pub struct start<'a>(&'a mut dyn ReadWrite);
        pub struct started<'a>(&'a mut dyn ReadWrite);
        impl<'a> start<'a> {
            pub fn new(a : &'a mut dyn ReadWrite) -> start<'a> {
                start(a)
            }
            pub fn next(self) -> started<'a> {
                started(self.0)
            }
        }
        impl<'a> started<'a> {
            pub fn get_stream<'b>(a: super::get_s::get_s<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }
    pub mod  get_s {
        use super::*;
        pub struct get_s<'a, 'b>(pub &'b mut super::start::started<'a>);
        pub struct got_s<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> get_s<'a, 'b> {
            pub fn next<C>(self, ctx: &secp256k1::Secp256k1<C>) -> (PublicKey, got_s<'b>)
            where C: secp256k1::Signing
            {
                let r : &'b mut dyn ReadWrite = super::start::started::get_stream(self);
                let mut buffer = [0u8; 33];
                r.read_exact(&mut buffer).unwrap();
                let mut s = PublicKey::from_slice(ctx, &buffer).unwrap();
                (s, got_s(r))
            }
        }

        impl<'a> got_s<'a> {
            pub fn get_stream<'b>(a: super::send_r::send_r<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }

    pub mod  send_r {
        use super::*;
        pub struct send_r<'a, 'b>(pub &'b mut super::get_s::got_s<'a>);
        pub struct sent_r<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> send_r<'a, 'b> {
            pub fn next(self, r : &PublicKey) -> sent_r<'b> {
                let w : &'b mut dyn ReadWrite = super::get_s::got_s::get_stream(self);
                w.write_all(&r.serialize());
                w.flush();
                sent_r(w)
            }
        }

        impl<'a> sent_r<'a> {
            pub fn get_stream<'b>(a: super::get_es::get_es<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }

    pub mod  get_es {
        use super::*;
        pub struct get_es<'a, 'b>(pub &'b mut super::send_r::sent_r<'a>);
        pub struct got_m(pub [u8;32]);
        impl<'a,'b> get_es<'a,'b> {
            pub fn next<C>(self, ctx : &secp256k1::Secp256k1<C>, choice: u8, key: &[u8]) -> got_m {
                let r : &'b mut dyn ReadWrite = super::send_r::sent_r::get_stream(self);
                // MUST BE CONSTANT TIME
                let mut result = [[0u8;32]; 256];
                for buffer in result.iter_mut() {
                    r.read_exact(buffer).unwrap();
                }
                for buffer in result.iter_mut() {
                    cipher(buffer, key);
                }
                got_m(result[choice as usize])
            }
        }
    }
}


pub fn run<T>(ctx: &secp256k1::Secp256k1<T>, choice: u8, peer: &mut dyn ReadWrite) -> [u8; 32]
where T: secp256k1::Verification + secp256k1::Signing
{
    let protocol = protocol::start::start::new(peer);
    let x = generate_key(ctx);
    let mut started = protocol.next();
    let (mut s, mut got_s) = protocol::get_s::get_s(&mut started).next(ctx);
    // check s != G
    assert_ne!(PublicKey::from_secret_key(ctx,&ONE_KEY), s);
    println!("Recieved S = {:?}", s);

    // compute H(S)
    let mut t = oracle(ctx, &s);
    println!("Receiver Computed T = {:?}", t);
    let mut choice_key = [0u8;32];
    choice_key[31] = choice;
    let c = SecretKey::from_slice(ctx, &choice_key).unwrap();
    t.mul_assign(ctx, &c);
    t.add_exp_assign(ctx, &x);
    // Send Over R = t
    println!("Receiver Computed R = {:?}", t);
    let mut sent_r = protocol::send_r::send_r(&mut got_s).next(&t);

    let mut h = Sha256::new().chain(&s.serialize()[0..]).chain(&t.serialize()[0..]);
    s.mul_assign(ctx, &x);
    println!("Receiver Shared Key is: {:?}", s);
    let k = h.chain(&s.serialize()[0..]).result();

    println!("Receiver Computed K_{} = {:?}",choice, k);
    // recv msg
    protocol::get_es::get_es(&mut sent_r).next(ctx,  choice, k.as_slice()).0
}


