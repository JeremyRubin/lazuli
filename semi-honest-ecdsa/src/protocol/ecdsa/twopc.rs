pub use sha2::{Digest, Sha256};
pub fn run<T: 'static>(m: &[u64; 4], mut peer: T) -> secp256k1::Signature
where
    T: crate::util::ReadWrite + crate::util::HasTryClone,
{
    let ctx = &secp256k1::Secp256k1::new();
    let key = crate::scalars::random_scalar();
    let nonce = crate::scalars::random_scalar();
    let i_nonce = crate::scalars::secp256k1_scalar_inverse(&nonce);

    let b32 = crate::scalars::bytes_from_scalar(&key);

    let ctx = &secp256k1::Secp256k1::new();
    let my_pk = secp256k1::PublicKey::from_secret_key(
        &ctx,
        &secp256k1::SecretKey::from_slice(ctx, &b32).unwrap(),
    );
    peer.write_all(&my_pk.serialize()[..]);
    peer.flush();

    let peer_pk = {
        let mut x = [0u8; 33];
        peer.read_exact(&mut x[..]).unwrap();
        secp256k1::PublicKey::from_slice(ctx, &x).unwrap()
    };
    assert_ne!(peer_pk, my_pk);
    let leader = my_pk > peer_pk;
    let mut keys = if leader {
        [peer_pk, my_pk]
    } else {
        [my_pk, peer_pk]
    };

    let l = Sha256::new()
        .chain(&keys[0].serialize()[..])
        .chain(&keys[1].serialize()[..])
        .result();
    let lx = Sha256::new().chain(l.as_slice());
    let (my_lxk, our_key) = {
        let my_lxk = {
            let h = lx.clone().chain(&my_pk.serialize()[..]).result();
            let mut z = [0u8; 32];
            z.clone_from_slice(&h.as_slice());
            let hs = crate::scalars::secp256k1_scalar_set_b32(&z);
            crate::scalars::secp256k1_scalar_mul(&hs, &key)
        };
        let mut start_key = secp256k1::PublicKey::from_secret_key(
            ctx,
            &secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&my_lxk))
                .unwrap(),
        );
        start_key = keys
            .iter_mut()
            .filter(|k| **k != my_pk)
            .try_fold(start_key, |acc, k| {
                let h = lx.clone().chain(&k.serialize()[..]).result();
                k.mul_assign(ctx, &secp256k1::SecretKey::from_slice(ctx, &h.as_slice())?);
                start_key.combine(ctx, k)
            }).unwrap();
        (my_lxk, start_key)
    };
    println!("Our Key is {:?}", our_key);

    // We have
    // q2q1( M + r (k1 + k2))
    // q2q1 ( (M+rk1) + rk2 )
    // q2 ( q1(M+rk1) + OT*(q1,rk2) )
    // q2 ( g_0 + g_1 + g_2 )
    // q2 ((g_0 + g_1) + g_2 )
    // q2 ( d_1 + d_2 )
    //  ( OT*(q2,d_1) + q2d_2 )
    //  ( t_0 + t_1 + t_2 )
    //  (t_0 + (t_1 + t_2) )
    //  (s_0 + s_1 )

    let r = {
        let b32_nonce =
            secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&nonce)[..])
                .unwrap();
        if leader {
            let kG = secp256k1::PublicKey::from_secret_key(ctx, &b32_nonce);
            peer.write_all(&kG.serialize()[..]);
            peer.flush();
            let mut xb = [0; 32];
            peer.read_exact(&mut xb[..]);
            println!("Leader receive kkG");
            crate::scalars::secp256k1_scalar_set_b32(&xb)
        } else {
            let b32_nonce = secp256k1::SecretKey::from_slice(
                ctx,
                &crate::scalars::bytes_from_scalar(&nonce)[..],
            ).unwrap();
            let kkG = {
                let mut b33 = [0u8; 33];
                peer.read_exact(&mut b33[..]);
                println!("Follower Read kG");
                let mut kG = secp256k1::PublicKey::from_slice(ctx, &b33).unwrap();
                kG.mul_assign(ctx, &b32_nonce);
                kG
            };
            peer.write_all(&kkG.serialize()[1..]).unwrap();
            peer.flush();
            println!("Follower sent kkG");

            let mut xb = [0; 32];
            xb[..].clone_from_slice(&kkG.serialize()[1..]);
            crate::scalars::secp256k1_scalar_set_b32(&xb)
        }
    };
    let s = if leader {
        let mut kx_m = crate::scalars::secp256k1_scalar_mul(&my_lxk, &r);
        crate::scalars::secp256k1_scalar_add_assign(&mut kx_m, &m);
        // kx_m = M + r k

        // kx_m_in = g_0
        let kx_m_in = crate::scalars::secp256k1_scalar_mul(&i_nonce, &kx_m);

        // They Will Request
        // gamma1 = g_1
        println!("Leader awaits gamma1");
        let gamma1 = {
            let mut gamma1 =
                crate::protocol::mult::receiver::run_scale_free(&i_nonce, &mut peer.try_clone());
            println!("Leader receive gamma1");
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma1, &kx_m_in);
            gamma1
        };
        // gamma1 = d_1

        // We will request
        // gamma2 = t_0 = s_0
        let gamma2 = crate::protocol::mult::sender::run_scale_free(&gamma1, peer.try_clone());
        std::thread::sleep(std::time::Duration::from_secs(1));
        println!("Leader receive gamma2");
        // Share it gamma2 to construct fina sig..
        peer.write_all(&crate::scalars::bytes_from_scalar(&gamma2)[..])
            .unwrap();
        peer.flush();
        let gamma3 = {
            let mut buf = [0; 32];
            peer.read_exact(&mut buf[..]);
            // gamma3 = s_1
            let mut gamma3 = crate::scalars::secp256k1_scalar_set_b32(&buf);
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma3, &gamma2);
            gamma3
        };
        gamma3
    } else {
        // kx = rk2
        let kx = crate::scalars::secp256k1_scalar_mul(&my_lxk, &r);
        // We Will Request
        // gamma1 = g_2 = d_2
        let gamma1 = crate::protocol::mult::sender::run_scale_free(&kx, peer.try_clone());
        println!("Follower receive gamma1");
        // They will request
        // gamma1_in = d_2 * q2 = t_2
        let gamma1_in = crate::scalars::secp256k1_scalar_mul(&i_nonce, &gamma1);
        std::thread::sleep(std::time::Duration::from_secs(1));
        // gamma2 = t_1
        let gamma2 = {
            let mut gamma2 =
                crate::protocol::mult::receiver::run_scale_free(&i_nonce, &mut peer.try_clone());
            println!("Follower receive gamma2");
            // t1+t2 = s_1
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma2, &gamma1_in);
            gamma2
        };

        // Share s_1
        peer.write_all(&crate::scalars::bytes_from_scalar(&gamma2)[..])
            .unwrap();
        peer.flush();
        // Read s_0 into xb
        let gamma3 = {
            let mut xb = [0; 32];
            peer.read_exact(&mut xb[..]);
            let mut gamma3 = crate::scalars::secp256k1_scalar_set_b32(&xb);
            // s_0+s_1
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma3, &gamma2);
            gamma3
        };
        println!("Follower finish signature");
        gamma3
    };
    let mut x = [0; 64];
    x[0..=31].clone_from_slice(&crate::scalars::bytes_from_scalar(&r)[..]);
    x[32..].clone_from_slice(&crate::scalars::bytes_from_scalar(&s)[..]);

    let mut sig = secp256k1::Signature::from_compact(ctx, &x[..]).unwrap();
    sig.normalize_s(ctx);

    println!("Sig: {:?}\n{:?}", &x[..], sig);

    let msg = secp256k1::Message::from_slice(&crate::scalars::bytes_from_scalar(&m)[..]).unwrap();
    if let Err(x) = ctx.verify(&msg, &sig, &our_key) {
        panic!(x);
    };
    sig
}
