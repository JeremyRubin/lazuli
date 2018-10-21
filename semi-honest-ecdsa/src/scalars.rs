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
        r[x] = b32[31 - i] as u64 | (b32[30 - i] as u64) << 8 | (b32[29 - i] as u64) << 16
            | (b32[28 - i] as u64) << 24 | (b32[27 - i] as u64) << 32
            | (b32[26 - i] as u64) << 40 | (b32[25 - i] as u64) << 48
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

}
