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
            pub fn get_stream<'b>(a: super::send_s::send_s<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }

    pub mod  send_s {
        use super::*;
        pub struct send_s<'a, 'b>(pub &'b mut super::start::started<'a>);
        pub struct sent_s<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> send_s<'a, 'b> {
            pub fn next(self, s : &PublicKey) -> sent_s<'b> {
                let w : &'b mut dyn ReadWrite = super::start::started::get_stream(self);
                w.write_all(&s.serialize());
                w.flush();
                sent_s(w)
            }
        }

        impl<'a> sent_s<'a> {
            pub fn get_stream<'b>(a: super::get_r::get_r<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }


    pub mod  get_r {
        use super::*;
        pub struct get_r<'a, 'b>(pub &'b mut super::send_s::sent_s<'a>);
        pub struct got_r<'a>(&'a mut dyn ReadWrite);
        impl<'a, 'b> get_r<'a, 'b> {
            pub fn next<C>(self, ctx: &secp256k1::Secp256k1<C>) -> (PublicKey, got_r<'b>)
            where C: secp256k1::Signing
            {
                let rd : &'b mut dyn ReadWrite = super::send_s::sent_s::get_stream(self);
                let mut buffer = [0u8; 33];
                rd.read_exact(&mut buffer).unwrap();
                let mut r = PublicKey::from_slice(ctx, &buffer).unwrap();
                (r, got_r(rd))
            }
        }

        impl<'a> got_r<'a> {
            pub fn get_stream<'b>(a: super::send_es::send_es<'a,'b>) -> &'b mut dyn ReadWrite {
                (a.0).0
            }
        }
    }
    pub mod  send_es {
        use super::*;
        pub struct send_es<'a, 'b>(pub &'b mut super::get_r::got_r<'a>);
        pub struct sent_es(());
        impl<'a,'b> send_es<'a,'b> {
            pub fn next<C>(self, ctx : &secp256k1::Secp256k1<C>, msg: &Vec<[u8;32]>) -> sent_es {
                let r : &'b mut dyn ReadWrite = super::get_r::got_r::get_stream(self);
                for m in msg {
                    r.write_all(&m[0..]);
                }
                r.flush();
                sent_es(())
            }
        }
    }
}


pub fn run<T>(ctx: &secp256k1::Secp256k1<T>, msg: &mut Vec<[u8;32]>, peer: &mut dyn ReadWrite) 
where T: secp256k1::Verification + secp256k1::Signing
{
    let protocol = protocol::start::start::new(peer);
    let mut started = protocol.next();
    // y <- Z_p
    let y = generate_key(ctx);
    // S = yG
    let s = PublicKey::from_secret_key(ctx, &y);
    println!("Sender's S = {:?}", s);
    let mut sent_s = protocol::send_s::send_s(&mut started).next(&s);
    // T = Oracle(s)
    let mut t = oracle(ctx, &s);
    println!("Sender Computed T = {:?}", t);
    // Get R from receiver 
    let (mut r, mut got_r) = protocol::get_r::get_r(&mut sent_s).next(ctx);
    println!("Sender Got R = {:?}", r);

    // h = H_{S,R}
    let h = Sha256::new().chain(&s.serialize()[0..]).chain(&r.serialize()[0..]);

    // T := -y T
    t.mul_assign(ctx, &negate(ctx, &y));

    // R := y R
    r.mul_assign(ctx, &y);
    // R = n(-y T) + y R where n = 0

    for (i,x) in msg.iter_mut().enumerate() {
        let mut h_ = h.clone().chain(&r.serialize()[0..]).result();

        if (i == 5) {
            println!("Receiver Shared Key is: {:?}", r);
            println!("Sender Computed K_{} = {:?}",i, h_);
        }
        // encrypt
        cipher(x, &h_.as_slice()); 
        // next key...
        // -y (n+1) T
        r = r.combine(ctx,&t).unwrap();
    }
    protocol::send_es::send_es(&mut got_r).next(ctx, msg);


}
