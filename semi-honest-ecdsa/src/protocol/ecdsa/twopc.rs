pub use sha2::{Digest, Sha256};
pub fn run<T: 'static, Inv>(
    get_inverse: Inv,
    m: &[u64; 4],
    mut peer: T,
) -> Option<secp256k1::Signature>
where
    T: crate::util::ReadWrite + crate::util::HasTryClone,
    Inv: FnOnce() -> super::util::Inverse,
{
    // start computing nonce *now*, inverse is slow
    let inverse = get_inverse();
    let key = crate::scalars::random_scalar();

    let b32 = crate::scalars::bytes_from_scalar(&key);

    let ctx = &secp256k1::Secp256k1::new();
    let my_pk = secp256k1::PublicKey::from_secret_key(
        &ctx,
        &secp256k1::SecretKey::from_slice(ctx, &b32).ok()?,
    );
    peer.write_all(&my_pk.serialize()[..]).ok()?;
    peer.flush().ok()?;

    let peer_pk = {
        let mut x = [0u8; 33];
        peer.read_exact(&mut x[..]).ok()?;
        secp256k1::PublicKey::from_slice(ctx, &x).ok()?
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

    let my_tweaked_pk = {
        let h = lx.clone().chain(&my_pk.serialize()[..]).result();
        let mut z = [0u8; 32];
        z.clone_from_slice(&h.as_slice());
        let hs = crate::scalars::secp256k1_scalar_set_b32(&z);
        crate::scalars::secp256k1_scalar_mul(&hs, &key)
    };
    let our_key = {
        keys.iter_mut()
            .filter(|k| **k != my_pk)
            .try_fold(
                secp256k1::PublicKey::from_secret_key(
                    ctx,
                    &secp256k1::SecretKey::from_slice(
                        ctx,
                        &crate::scalars::bytes_from_scalar(&my_tweaked_pk),
                    ).ok()?,
                ),
                |acc, k| {
                    let h = lx.clone().chain(&k.serialize()[..]).result();
                    k.mul_assign(ctx, &secp256k1::SecretKey::from_slice(ctx, &h.as_slice())?)?;
                    acc.combine(ctx, k)
                },
            ).ok()?
    };

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

    let (r, s) = if leader {
        run_leader(ctx, m, inverse, &my_tweaked_pk, peer)?
    } else {
        run_follower(ctx, inverse, &my_tweaked_pk, peer)?
    };
    let mut x = [0; 64];
    x[0..=31].clone_from_slice(&crate::scalars::bytes_from_scalar(&r)[..]);
    x[32..].clone_from_slice(&crate::scalars::bytes_from_scalar(&s)[..]);

    let mut sig = secp256k1::Signature::from_compact(ctx, &x[..]).ok()?;
    sig.normalize_s(ctx);

    let msg = secp256k1::Message::from_slice(&crate::scalars::bytes_from_scalar(&m)[..]).ok()?;
    ctx.verify(&msg, &sig, &our_key).ok()?;
    Some(sig)
}

fn run_leader<T: 'static, C>(
    ctx: &secp256k1::Secp256k1<C>,
    m: &[u64; 4],
    nonce_pair: super::util::Inverse,
    my_tweaked_pk: &[u64; 4],
    mut peer: T,
) -> Option<(crate::scalars::scalar, crate::scalars::scalar)>
where
    T: crate::util::ReadWrite + crate::util::HasTryClone,
    C: secp256k1::Signing + secp256k1::Verification,
{
    let nonce = nonce_pair.0;
    let r = {
        let b32_nonce =
            secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&nonce)[..])
                .ok()?;
        let k_g = secp256k1::PublicKey::from_secret_key(ctx, &b32_nonce);
        peer.write_all(&k_g.serialize()[..]).ok()?;
        peer.flush().ok()?;
        let mut xb = [0; 32];
        peer.read_exact(&mut xb[..]).ok()?;
        crate::scalars::secp256k1_scalar_set_b32(&xb)
    };
    let s = {
        let mut kx_m = crate::scalars::secp256k1_scalar_mul(my_tweaked_pk, &r);
        crate::scalars::secp256k1_scalar_add_assign(&mut kx_m, &m);
        // kx_m = M + r k

        // kx_m_in = g_0
        let i_nonce = nonce_pair.1.join().ok()?;
        let kx_m_in = crate::scalars::secp256k1_scalar_mul(&i_nonce, &kx_m);

        // They Will Request
        // gamma1 = g_1
        let gamma1 = {
            let mut gamma1 =
                crate::protocol::mult::receiver::run_scale_free(&i_nonce, peer.try_clone())
                    .join()
                    .ok()?;
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma1, &kx_m_in);
            gamma1
        };
        // gamma1 = d_1

        // We will request
        // gamma2 = t_0 = s_0
        let (gamma2, th) = crate::protocol::mult::sender::run_scale_free(&gamma1, peer.try_clone());
        th.join().ok()?;
        // Share it gamma2 to construct fina sig..
        peer.write_all(&crate::scalars::bytes_from_scalar(&gamma2)[..])
            .ok()?;
        peer.flush().ok()?;
        let gamma3 = {
            let mut buf = [0; 32];
            peer.read_exact(&mut buf[..]).ok()?;
            // gamma3 = s_1
            let mut gamma3 = crate::scalars::secp256k1_scalar_set_b32(&buf);
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma3, &gamma2);
            gamma3
        };
        gamma3
    };
    Some((r, s))
}

fn run_follower<T: 'static, C>(
    ctx: &secp256k1::Secp256k1<C>,
    nonce_pair: super::util::Inverse,
    my_tweaked_pk: &[u64; 4],
    mut peer: T,
) -> Option<(crate::scalars::scalar, crate::scalars::scalar)>
where
    T: crate::util::ReadWrite + crate::util::HasTryClone,
    C: secp256k1::Signing + secp256k1::Verification,
{
    let nonce = nonce_pair.0;
    let r = {
        let b32_nonce =
            secp256k1::SecretKey::from_slice(ctx, &crate::scalars::bytes_from_scalar(&nonce)[..])
                .ok()?;
        let kk_g = {
            let mut b33 = [0u8; 33];
            peer.read_exact(&mut b33[..]).ok()?;
            let mut k_g = secp256k1::PublicKey::from_slice(ctx, &b33).ok()?;
            k_g.mul_assign(ctx, &b32_nonce).ok()?;
            k_g
        };
        peer.write_all(&kk_g.serialize()[1..]).ok()?;
        peer.flush().ok()?;

        let mut xb = [0; 32];
        xb[..].clone_from_slice(&kk_g.serialize()[1..]);
        crate::scalars::secp256k1_scalar_set_b32(&xb)
    };
    let s = {
        // kx = rk2
        let kx = crate::scalars::secp256k1_scalar_mul(my_tweaked_pk, &r);
        // We Will Request
        // gamma1 = g_2 = d_2
        let (gamma1, wait_before_send) =
            crate::protocol::mult::sender::run_scale_free(&kx, peer.try_clone());
        // They will request
        // gamma1_in = d_2 * q2 = t_2
        let i_nonce = nonce_pair.1.join().ok()?;
        let gamma1_in = crate::scalars::secp256k1_scalar_mul(&i_nonce, &gamma1);
        wait_before_send.join().ok()?;
        // gamma2 = t_1
        let gamma2 = {
            let mut gamma2 =
                crate::protocol::mult::receiver::run_scale_free(&i_nonce, peer.try_clone())
                    .join()
                    .ok()?;
            // t1+t2 = s_1
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma2, &gamma1_in);
            gamma2
        };

        // Share s_1
        peer.write_all(&crate::scalars::bytes_from_scalar(&gamma2)[..])
            .ok()?;
        peer.flush().ok()?;
        // Read s_0 into xb
        let gamma3 = {
            let mut xb = [0; 32];
            peer.read_exact(&mut xb[..]).ok()?;
            let mut gamma3 = crate::scalars::secp256k1_scalar_set_b32(&xb);
            // s_0+s_1
            crate::scalars::secp256k1_scalar_add_assign(&mut gamma3, &gamma2);
            gamma3
        };
        gamma3
    };
    Some((r, s))
}
