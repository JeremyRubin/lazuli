/* Limbs of the secp256k1 order. */
const SECP256K1_N_0: u64 = 0xBFD25E8CD0364141u64;
const SECP256K1_N_1: u64 = 0xBAAEDCE6AF48A03Bu64;
const SECP256K1_N_2: u64 = 0xFFFFFFFFFFFFFFFEu64;
const SECP256K1_N_3: u64 = 0xFFFFFFFFFFFFFFFFu64;

/* Limbs of 2^256 minus the secp256k1 order. */
const SECP256K1_N_C_0: u64 = (!SECP256K1_N_0) + 1u64;
const SECP256K1_N_C_1: u64 = !SECP256K1_N_1;
const SECP256K1_N_C_2: u64 = 1u64;

/* Limbs of half the secp256k1 order. */
const SECP256K1_N_H_0: u64 = 0xDFE92F46681B20A0u64;
const SECP256K1_N_H_1: u64 = 0x5D576E7357A4501Du64;
const SECP256K1_N_H_2: u64 = 0xFFFFFFFFFFFFFFFFu64;
const SECP256K1_N_H_3: u64 = 0x7FFFFFFFFFFFFFFFu64;

pub fn secp256k1_scalar_negate(r: &mut scalar) {
    let nonzero = (!0u64) * ((*r != [0u64; 4]) as u64);
    let mut overflow = true;
    for (i, v) in [SECP256K1_N_0, SECP256K1_N_1, SECP256K1_N_2, SECP256K1_N_3]
        .iter()
        .enumerate()
    {
        let (t1, ov1) = (!r[i]).overflowing_add(overflow as u64);
        let (t2, ov2) = t1.overflowing_add(*v);
        r[i] = t2 & nonzero;
        overflow = ov1 | ov2;
    }
}

pub type scalar = [u64; 4];
pub fn bytes_from_scalar(r: &scalar) -> [u8; 32] {
    let mut bin = [0u8; 32];
    bin[0] = (r[3] >> 56) as u8;
    bin[1] = (r[3] >> 48) as u8;
    bin[2] = (r[3] >> 40) as u8;
    bin[3] = (r[3] >> 32) as u8;
    bin[4] = (r[3] >> 24) as u8;
    bin[5] = (r[3] >> 16) as u8;
    bin[6] = (r[3] >> 8) as u8;
    bin[7] = r[3] as u8;
    bin[8] = (r[2] >> 56) as u8;
    bin[9] = (r[2] >> 48) as u8;
    bin[10] = (r[2] >> 40) as u8;
    bin[11] = (r[2] >> 32) as u8;
    bin[12] = (r[2] >> 24) as u8;
    bin[13] = (r[2] >> 16) as u8;
    bin[14] = (r[2] >> 8) as u8;
    bin[15] = r[2] as u8;
    bin[16] = (r[1] >> 56) as u8;
    bin[17] = (r[1] >> 48) as u8;
    bin[18] = (r[1] >> 40) as u8;
    bin[19] = (r[1] >> 32) as u8;
    bin[20] = (r[1] >> 24) as u8;
    bin[21] = (r[1] >> 16) as u8;
    bin[22] = (r[1] >> 8) as u8;
    bin[23] = r[1] as u8;
    bin[24] = (r[0] >> 56) as u8;
    bin[25] = (r[0] >> 48) as u8;
    bin[26] = (r[0] >> 40) as u8;
    bin[27] = (r[0] >> 32) as u8;
    bin[28] = (r[0] >> 24) as u8;
    bin[29] = (r[0] >> 16) as u8;
    bin[30] = (r[0] >> 8) as u8;
    bin[31] = r[0] as u8;
    bin
}

pub fn secp256k1_scalar_set_b32(b32: &[u8; 32]) -> scalar {
    let mut r = [0u64; 4];
    let mut i = 0;
    for x in 0..=3 {
        r[x] = b32[31 - i] as u64
            | (b32[30 - i] as u64) << 8
            | (b32[29 - i] as u64) << 16
            | (b32[28 - i] as u64) << 24
            | (b32[27 - i] as u64) << 32
            | (b32[26 - i] as u64) << 40
            | (b32[25 - i] as u64) << 48
            | (b32[24 - i] as u64) << 56;
        i += 8;
    }
    let ov = secp256k1_scalar_check_overflow(&r);
    secp256k1_scalar_reduce(&mut r, ov);
    r
}

pub fn secp256k1_scalar_reduce(r: &mut scalar, overflow: bool) {
    //VERIFY_CHECK(overflow <= 1);
    let ov1 = overflow as u64;
    let mut overflow = false;
    for (i, v) in [SECP256K1_N_C_0, SECP256K1_N_C_1, SECP256K1_N_C_2]
        .iter()
        .enumerate()
    {
        let (t, ov2) = r[i].overflowing_add(v * ov1);
        let (t2, ov3) = t.overflowing_add(overflow as u64);
        r[i] = t2;
        overflow = ov2 | ov3;
    }
    r[3] = r[3].wrapping_add(overflow as u64);
}
pub fn secp256k1_scalar_add(r: &mut scalar, a: &scalar, b: &scalar) -> bool {
    let mut overflow = false;
    for i in 0..=3 {
        let (t, overflowed) = a[i].overflowing_add(b[i]);
        let (t2, overflowed2) = t.overflowing_add(overflow as u64);
        r[i] = t2;
        overflow = overflowed | overflowed2;
    }
    overflow |= secp256k1_scalar_check_overflow(&r);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

pub fn secp256k1_scalar_add_assign(r: &mut scalar, a: &scalar) -> bool {
    let mut overflow = false;
    for i in 0..=3 {
        let (t, overflowed) = a[i].overflowing_add(r[i]);
        let (t2, overflowed2) = t.overflowing_add(overflow as u64);
        r[i] = t2;
        overflow = overflowed | overflowed2;
    }
    overflow |= secp256k1_scalar_check_overflow(&r);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

pub fn secp256k1_scalar_double(a: &mut scalar) -> bool {
    let mut overflow = false;
    for i in 0..=3 {
        let (t, overflowed) = a[i].overflowing_add(overflow as u64);
        let (t2, overflowed2) = t.overflowing_add(a[i]);
        a[i] = t2;
        overflow = overflowed | overflowed2;
    }
    overflow |= secp256k1_scalar_check_overflow(a);
    secp256k1_scalar_reduce(a, overflow);
    return overflow;
}

pub fn secp256k1_scalar_check_overflow(a: &scalar) -> bool {
    let mut yes = false;
    let mut no = false;
    no |= a[3] < SECP256K1_N_3; /* No need for a > check. */
    no |= a[2] < SECP256K1_N_2;
    yes |= (a[2] > SECP256K1_N_2) & !no;
    no |= a[1] < SECP256K1_N_1;
    yes |= (a[1] > SECP256K1_N_1) & !no;
    yes |= (a[0] >= SECP256K1_N_0) & !no;
    return yes;
}

pub fn non_constant_time_shift(a: &mut scalar, bytes: u8) {
    assert!(bytes <= 31);
    for i in 0..bytes * 8 {
        secp256k1_scalar_double(a);
    }
}

pub fn scalar_mul_by_256(s: &scalar) -> [scalar; 256] {
    let mut x: [scalar; 256] = [[0; 4]; 256];
    for i in 1..=255 {
        x[i] = x[i - 1];
        secp256k1_scalar_add_assign(&mut x[i], s);
    }
    x
}

use rand::prelude::*;
pub fn random_scalar() -> scalar {
    random()
}

pub fn assign_add(s: &mut [scalar; 256], c: &scalar) {
    for a in s.iter_mut() {
        secp256k1_scalar_add_assign(a, c);
    }
}

pub fn muladd2(a: u64, b: u64, c: &mut (u64, u64, u64)) {
    let mut t: u128 = (a as u128) * b as u128;
    let mut th: u64 = (t >> 64) as u64; /* at most 0xFFFFFFFFFFFFFFFE */

    let mut tl = t as u64;
    let (mut th2, ov1) = th.overflowing_add(th); /* at most 0xFFFFFFFFFFFFFFFE (in case th was 0x7FFFFFFFFFFFFFFF) */

    c.2 += ov1 as u64; /* never overflows by contract (verified the next line) */

    debug_assert!((th2 >= th) || (c.2 != 0));
    let (mut tl2, ov2) = tl.overflowing_add(tl); /* at most 0xFFFFFFFFFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFFFFFFFFFF) */

    th2 += ov2 as u64; /* at most 0xFFFFFFFFFFFFFFFF */

    let (c0_new, ov3) = c.0.overflowing_add(tl2); /* overflow is handled on the next line */

    c.0 = c0_new;
    th2 += ov3 as u64; /* second overflow is handled on the next line */

    c.2 += (ov3 & (th2 == 0)) as u64; /* never overflows by contract (verified the next line) */

    debug_assert!(!ov3 || (th2 != 0) || (c.2 != 0));
    let (c1_new, ov4) = c.1.overflowing_add(th2);
    c.1 = c1_new;
    c.2 += ov4 as u64; /* never overflows by contract (verified the next line) */

    debug_assert!(!ov4 || (c.2 != 0));
}

fn muladd_fast(a: u64, b: u64, c: &mut (u64, u64, u64)) {
    let t: u128 = a as u128 * b as u128;
    let mut th = (t >> 64) as u64; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u64;
    let (c0_new, overflowed) = c.0.overflowing_add(tl);
    c.0 = c0_new; /* overflow is handled on the next line */

    th += overflowed as u64; /* at most 0xFFFFFFFFFFFFFFFF */

    c.1 += th; /* never overflows by contract (verified in the next line) */

    debug_assert!(c.1 >= th);
}

fn muladd(a: u64, b: u64, c: &mut (u64, u64, u64)) {
    let t: u128 = a as u128 * b as u128;
    let mut th = (t >> 64) as u64; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u64;
    let (c0_new, overflowed) = c.0.overflowing_add(tl);
    c.0 = c0_new; /* overflow is handled on the next line */

    th += overflowed as u64; /* at most 0xFFFFFFFFFFFFFFFF */

    let (c1_new, overflowed2) = c.1.overflowing_add(th);
    c.1 = c1_new; /* overflow is handled on the next line */

    c.2 += overflowed2 as u64; /* never overflows by contract (verified in the next line) */

    debug_assert!((c.1 >= th) || (c.2 != 0));
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
fn extract(n: &mut u64, c: &mut (u64, u64, u64)) {
    *n = c.0;
    c.0 = c.1;
    c.1 = c.2;
    c.2 = 0;
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
fn extract_fast(n: &mut u64, c: &mut (u64, u64, u64)) {
    debug_assert!(c.2 == 0);
    *n = c.0;
    c.0 = c.1;
    c.1 = 0;
}

pub fn secp256k1_scalar_mul_512(a: &scalar, b: &scalar) -> [u64; 8] {
    let mut l = [0u64; 8];
    let mut c = (0, 0, 0);
    let c = &mut c;

    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a[0], b[0], c);
    extract_fast(&mut l[0], c);
    muladd(a[0], b[1], c);
    muladd(a[1], b[0], c);
    extract(&mut l[1], c);
    muladd(a[0], b[2], c);
    muladd(a[1], b[1], c);
    muladd(a[2], b[0], c);
    extract(&mut l[2], c);
    muladd(a[0], b[3], c);
    muladd(a[1], b[2], c);
    muladd(a[2], b[1], c);
    muladd(a[3], b[0], c);
    extract(&mut l[3], c);
    muladd(a[1], b[3], c);
    muladd(a[2], b[2], c);
    muladd(a[3], b[1], c);
    extract(&mut l[4], c);
    muladd(a[2], b[3], c);
    muladd(a[3], b[2], c);
    extract(&mut l[5], c);
    muladd_fast(a[3], b[3], c);
    extract_fast(&mut l[6], c);
    debug_assert!(c.1 == 0);
    l[7] = c.0;
    l
}

pub fn secp256k1_scalar_sqr_512(a: &scalar) -> [u64; 8] {
    let mut l = [0u64; 8];
    let mut c = (0, 0, 0);
    let c = &mut c;
    /* 160 bit accumulator. */
    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a[0], a[0], c);
    extract_fast(&mut l[0], c);
    muladd2(a[0], a[1], c);
    extract(&mut l[1], c);
    muladd2(a[0], a[2], c);
    muladd(a[1], a[1], c);
    extract(&mut l[2], c);
    muladd2(a[0], a[3], c);
    muladd2(a[1], a[2], c);
    extract(&mut l[3], c);
    muladd2(a[1], a[3], c);
    muladd(a[2], a[2], c);
    extract(&mut l[4], c);
    muladd2(a[2], a[3], c);
    extract(&mut l[5], c);
    muladd_fast(a[3], a[3], c);
    extract_fast(&mut l[6], c);
    debug_assert!(c.1 == 0);
    l[7] = c.0;
    l
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
fn sumadd(a: u64, c: &mut (u64, u64, u64)) {
    let (c0_new, over) = c.0.overflowing_add(a);
    c.0 = c0_new;
    let (c1_new, over2) = c.1.overflowing_add(over as u64); /* overflow is handled on the next line */
    c.1 = c1_new;
    c.2 += over2 as u64; /* never overflows by contract */
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
fn sumadd_fast(a: u64, c: &mut (u64, u64, u64)) {
    let (c0_new, over) = c.0.overflowing_add(a);
    c.0 = c0_new;
    c.1 = c.1.wrapping_add(over as u64); /* overflow is handled on the next line */
    debug_assert!((c.1 != 0) | (c.0 >= a));
    debug_assert!(c.2 == 0);
}

pub fn secp256k1_scalar_reduce_512(l: &[u64; 8]) -> scalar {
    let mut p0 = 0;
    let mut p1 = 0;
    let mut p2 = 0;
    let mut p3 = 0;
    let mut p4 = 0u32;
    {
        let mut c = (0, 0, 0);
        let c = &mut c;
        let n = (l[4], l[5], l[6], l[7]);
        let mut m0 = 0;
        let mut m1 = 0;
        let mut m2 = 0;
        let mut m3 = 0;
        let mut m4 = 0;
        let mut m5 = 0;
        let mut m6 = 0u32;
        /* Reduce 512 bits into 385. */
        /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
        *c = (l[0], 0, 0);
        muladd_fast(n.0, SECP256K1_N_C_0, c);
        extract_fast(&mut m0, c);
        sumadd_fast(l[1], c);
        muladd(n.1, SECP256K1_N_C_0, c);
        muladd(n.0, SECP256K1_N_C_1, c);
        extract(&mut m1, c);
        sumadd(l[2], c);
        muladd(n.2, SECP256K1_N_C_0, c);
        muladd(n.1, SECP256K1_N_C_1, c);
        sumadd(n.0, c);
        extract(&mut m2, c);
        sumadd(l[3], c);
        muladd(n.3, SECP256K1_N_C_0, c);
        muladd(n.2, SECP256K1_N_C_1, c);
        sumadd(n.1, c);
        extract(&mut m3, c);
        muladd(n.3, SECP256K1_N_C_1, c);
        sumadd(n.2, c);
        extract(&mut m4, c);
        sumadd_fast(n.3, c);
        extract_fast(&mut m5, c);
        debug_assert!(c.0 <= 1);
        m6 = c.0 as u32;

        /* Reduce 385 bits into 258. */
        /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
        *c = (m0, 0, 0);
        muladd_fast(m4, SECP256K1_N_C_0, c);
        extract_fast(&mut p0, c);
        sumadd_fast(m1, c);
        muladd(m5, SECP256K1_N_C_0, c);
        muladd(m4, SECP256K1_N_C_1, c);
        extract(&mut p1, c);
        sumadd(m2, c);
        muladd(m6 as u64, SECP256K1_N_C_0, c);
        muladd(m5, SECP256K1_N_C_1, c);
        sumadd(m4, c);
        extract(&mut p2, c);
        sumadd_fast(m3, c);
        muladd_fast(m6 as u64, SECP256K1_N_C_1, c);
        sumadd_fast(m5, c);
        extract_fast(&mut p3, c);
        p4 = c.0 as u32 + m6;
        debug_assert!(p4 <= 2);
    }

    /* Reduce 258 bits into 256. */
    /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */

    {
        let mut r = [0; 4];
        let mut c: u128 = p0 as u128 + SECP256K1_N_C_0 as u128 * p4 as u128;
        r[0] = c as u64;
        c >>= 64;
        c += p1 as u128 + SECP256K1_N_C_1 as u128 * p4 as u128;
        r[1] = c as u64;
        c >>= 64;
        c += p2 as u128 + p4 as u128;
        r[2] = c as u64;
        c >>= 64;
        c += p3 as u128;
        r[3] = c as u64;
        c >>= 64;
        /* Final reduction of r. */
        let overflow = (c > 0) | secp256k1_scalar_check_overflow(&r);
        secp256k1_scalar_reduce(&mut r, overflow);
        return r;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use secp256k1::key::*;
    #[test]
    fn scalar_add_basic() {
        let a = [0, 1, 2, 3];
        let b = [4, 5, 6, 7];
        let c = [4, 6, 8, 10];
        let mut r = [0u64; 4];
        secp256k1_scalar_add(&mut r, &a, &b);
        assert_eq!(c, r);
    }

    #[test]
    fn scalar_add_overflows_byte_bound_0() {
        let a = [!0u64, 1, 2, 0u64];
        let b = [1u64, 5, 6, 1];
        let c = [0u64, 7, 8, 1];
        let mut r = [0u64; 4];
        let overflowed = secp256k1_scalar_add(&mut r, &a, &b);
        assert!(!overflowed);
        assert_eq!(c, r);
    }

    #[test]
    fn scalar_add_overflows_byte_bound_1() {
        let a = [0, !0u64, 1, 2];
        let b = [1, 1u64, 5, 6];
        let c = [1, 0, 7, 8];
        let mut r = [0u64; 4];
        let overflowed = secp256k1_scalar_add(&mut r, &a, &b);
        assert!(!overflowed);
        assert_eq!(c, r);
    }

    #[test]
    fn scalar_add_overflows_byte_bound_2() {
        let a = [2, 0, !0u64, 1];
        let b = [6, 1, 1u64, 5];
        let c = [8, 1, 0, 7];
        let mut r = [0u64; 4];
        let overflowed = secp256k1_scalar_add(&mut r, &a, &b);
        assert!(!overflowed);
        assert_eq!(c, r);
    }

    #[test]
    fn scalar_add_negate_zero_random() {
        let a = random_scalar();
        let mut b = a.clone();
        secp256k1_scalar_negate(&mut b);
        secp256k1_scalar_add_assign(&mut b, &a);

        let r = [0u64; 4];
        assert_eq!(b, r);
    }
    #[test]
    fn scalar_add_negate_ones() {
        let a = [1; 4];
        let mut b = a.clone();
        secp256k1_scalar_negate(&mut b);
        secp256k1_scalar_add_assign(&mut b, &a);

        let r = [0u64; 4];
        assert_eq!(b, r);
    }
    #[test]
    fn scalar_double_flows() {
        let mut a = [1 << 63, 0, 0, 0];
        secp256k1_scalar_double(&mut a);
        assert_eq!(a, [0, 1, 0, 0]);
    }
    #[test]
    fn scalar_non_constant_time_shift() {
        let mut a = [1, 0, 0, 0];
        non_constant_time_shift(&mut a, 8);
        assert_eq!(a, [0, 1, 0, 0]);

        let mut a = [1, 0, 1, 0];
        non_constant_time_shift(&mut a, 8);
        assert_eq!(a, [0, 1, 0, 1]);
    }

    #[test]
    fn scalar_add_compat() {
        let ctx = &secp256k1::Secp256k1::new();
        let mut alpha: [u64; 4] = random();
        let mut s_alpha = SecretKey::from_slice(ctx, &bytes_from_scalar(&alpha)[..]).unwrap();
        let mut beta: [u64; 4] = random();
        let s_beta = SecretKey::from_slice(ctx, &bytes_from_scalar(&beta)[..]).unwrap();
        let mut r = [0u64; 4];
        secp256k1_scalar_add(&mut r, &alpha, &beta);
        let s_r = SecretKey::from_slice(ctx, &bytes_from_scalar(&r)[..]).unwrap();

        s_alpha.add_assign(ctx, &s_beta).unwrap();
        assert_eq!(s_alpha, s_r);
    }

    #[test]
    fn ser_de() {
        let x = random_scalar();
        let b32 = bytes_from_scalar(&x);
        let y = secp256k1_scalar_set_b32(&b32);
        assert_eq!(x, y);
    }

    #[test]
    fn assign_add_correct() {
        let mut x = random_scalar();
        let y = random_scalar();
        let mut xs = [x; 256];
        assign_add(&mut xs, &y);
        secp256k1_scalar_add_assign(&mut x, &y);
        assert_eq!(&xs[..], &[x; 256][..]);
    }
    #[test]
    fn scalar_mul_by_256_correct() {
        let x = [1, 0, 0, 0];
        let y = scalar_mul_by_256(&x);
        let v: Vec<_> = (0..256).map(|i| [i, 0, 0, 0]).collect();
        assert_eq!(v, &y[..]);
    }
    #[test]
    fn scalar_mul_correct() {
        let ctx = &secp256k1::Secp256k1::new();
        let mut alpha: [u64; 4] = random();
        let mut s_alpha = SecretKey::from_slice(ctx, &bytes_from_scalar(&alpha)[..]).unwrap();
        let mut beta: [u64; 4] = random();
        let s_beta = SecretKey::from_slice(ctx, &bytes_from_scalar(&beta)[..]).unwrap();
        let mut r = secp256k1_scalar_mul(&alpha, &beta);
        let s_r = SecretKey::from_slice(ctx, &bytes_from_scalar(&r)[..]).unwrap();

        s_alpha.mul_assign(ctx, &s_beta).unwrap();
        assert_eq!(s_alpha, s_r);
    }

    #[test]
    fn scalar_sqr_correct() {
        let ctx = &secp256k1::Secp256k1::new();
        let mut alpha: [u64; 4] = random();
        let mut s_alpha = SecretKey::from_slice(ctx, &bytes_from_scalar(&alpha)[..]).unwrap();
        let mut r = secp256k1_scalar_sqr(&alpha);
        let s_r = SecretKey::from_slice(ctx, &bytes_from_scalar(&r)[..]).unwrap();

        let s = s_alpha.clone();
        s_alpha.mul_assign(ctx, &s).unwrap();
        assert_eq!(s_alpha, s_r);
    }

    #[test]
    fn scalar_inv_correct() {
        let ctx = &secp256k1::Secp256k1::new();
        let mut alpha: [u64; 4] = random();
        let mut r = secp256k1_scalar_inverse(&alpha);
        let check = secp256k1_scalar_mul(&alpha, &r);
        assert_eq!(check, [1, 0, 0, 0]);
    }

}

pub fn secp256k1_scalar_mul(a: &scalar, b: &scalar) -> scalar {
    let l = secp256k1_scalar_mul_512(a, b);
    secp256k1_scalar_reduce_512(&l)
}

pub fn secp256k1_scalar_sqr(a: &scalar) -> scalar {
    let l = secp256k1_scalar_sqr_512(a);
    secp256k1_scalar_reduce_512(&l)
}

pub fn secp256k1_scalar_inverse(x: &scalar) -> scalar {
    /* First compute xN as x ^ (2^N - 1) for some values of N,
     * and uM as x ^ M for some values of M. */

    let u2 = secp256k1_scalar_sqr(x);
    let x2 = secp256k1_scalar_mul(&u2, x);
    let u5 = secp256k1_scalar_mul(&u2, &x2);
    let x3 = secp256k1_scalar_mul(&u5, &u2);
    let u9 = secp256k1_scalar_mul(&x3, &u2);
    let u11 = secp256k1_scalar_mul(&u9, &u2);
    let u13 = secp256k1_scalar_mul(&u11, &u2);

    let mut x6 = secp256k1_scalar_sqr(&u13);
    x6 = secp256k1_scalar_sqr(&x6);
    x6 = secp256k1_scalar_mul(&x6, &u11);

    let mut x8 = secp256k1_scalar_sqr(&x6);
    x8 = secp256k1_scalar_sqr(&x8);
    x8 = secp256k1_scalar_mul(&x8, &x2);

    let mut x14 = secp256k1_scalar_sqr(&x8);
    for _ in 0..5 {
        x14 = secp256k1_scalar_sqr(&x14);
    }
    x14 = secp256k1_scalar_mul(&x14, &x6);

    let mut x28 = secp256k1_scalar_sqr(&x14);
    for _ in 0..13 {
        x28 = secp256k1_scalar_sqr(&x28);
    }
    x28 = secp256k1_scalar_mul(&x28, &x14);

    let mut x56 = secp256k1_scalar_sqr(&x28);
    for _ in 0..27 {
        x56 = secp256k1_scalar_sqr(&x56);
    }
    x56 = secp256k1_scalar_mul(&x56, &x28);

    let mut x112 = secp256k1_scalar_sqr(&x56);
    for _ in 0..55 {
        x112 = secp256k1_scalar_sqr(&x112);
    }
    x112 = secp256k1_scalar_mul(&x112, &x56);

    let mut x126 = secp256k1_scalar_sqr(&x112);
    for _ in 0..13 {
        x126 = secp256k1_scalar_sqr(&x126);
    }
    x126 = secp256k1_scalar_mul(&x126, &x14);

    /* Then accumulate the final result (t starts at x126). */
    let t: &mut scalar = &mut x126;
    for _ in 0..3 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u5); /* 101 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u5); /* 101 */
    for _ in 0..5 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u11); /* 1011 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u11); /* 1011 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..5 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..6 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u13); /* 1101 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u5); /* 101 */
    for _ in 0..3 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..5 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u9); /* 1001 */
    for _ in 0..6 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u5); /* 101 */
    for _ in 0..10 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x3); /* 111 */
    for _ in 0..9 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x8); /* 11111111 */
    for _ in 0..5 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u9); /* 1001 */
    for _ in 0..6 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u11); /* 1011 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u13); /* 1101 */
    for _ in 0..5 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &x2); /* 11 */
    for _ in 0..6 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u13); /* 1101 */
    for _ in 0..10 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u13); /* 1101 */
    for _ in 0..4 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, &u9); /* 1001 */
    for _ in 0..6 {
        *t = secp256k1_scalar_sqr(t);
    }
    *t = secp256k1_scalar_mul(t, x); /* 1 */
    for _ in 0..8 {
        *t = secp256k1_scalar_sqr(t);
    }
    secp256k1_scalar_mul(t, &x6) /* 111111 */
}
