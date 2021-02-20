//  Copyright (C) 2020  Éloïs SANCHEZ.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Manage cryptographic operations for DUniter Protocols and the Duniter eco-system most broadly.
//!
//! Scrypt

pub mod params;

use std::{iter::repeat, mem::MaybeUninit, num::NonZeroU32, ptr};

const ITERATIONS: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

#[cfg(not(feature = "assembly"))]
#[cfg(not(tarpaulin_include))]
fn pbkdf2(salt: &[u8], password: &[u8], output: &mut [u8]) {
    let mut hmac = cryptoxide::hmac::Hmac::new(cryptoxide::sha2::Sha256::new(), password);
    cryptoxide::pbkdf2::pbkdf2(&mut hmac, salt, ITERATIONS.get(), output);
}
#[cfg(feature = "assembly")]
fn pbkdf2(salt: &[u8], password: &[u8], output: &mut [u8]) {
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        ITERATIONS,
        salt,
        password,
        output,
    );
}

/**
 * The scrypt key derivation function.
 *
 * # Arguments
 *
 * * `password` - The password to process as a byte vector
 * * `salt` - The salt value to use as a byte vector
 * * `params` - The `ScryptParams` to use
 * * `output` - The resulting derived key is returned in this byte vector.
 *
 */
pub fn scrypt(password: &[u8], salt: &[u8], params: &params::ScryptParams, output: &mut [u8]) {
    // This check required by Scrypt:
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    assert!(!output.is_empty());
    assert!(output.len() / 32 <= 0xffff_ffff);

    // The checks in the ScryptParams constructor guarantee that the following is safe:
    let n = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;
    let pr128 = (params.p as usize) * r128;
    let nr128 = n * r128;

    let mut b: Vec<u8> = repeat(0).take(pr128).collect();

    pbkdf2(salt, password, b.as_mut_slice());

    let mut v: Vec<u8> = repeat(0).take(nr128).collect();
    let mut t: Vec<u8> = repeat(0).take(r128).collect();

    for chunk in b.as_mut_slice().chunks_mut(r128) {
        scrypt_ro_mix(chunk, v.as_mut_slice(), t.as_mut_slice(), n);
    }

    pbkdf2(&b, password, output);
}

// Execute the ROMix operation in-place.
// b - the data to operate on
// v - a temporary variable to store the vector V
// t - a temporary variable to store the result of the xor
// n - the scrypt parameter N
#[allow(clippy::many_single_char_names)]
fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize) {
    fn integerify(x: &[u8], n: usize) -> usize {
        // n is a power of 2, so n - 1 gives us a bitmask that we can use to perform a calculation
        // mod n using a simple bitwise and.
        let mask = n - 1;
        // This cast is safe since we're going to get the value mod n (which is a power of 2), so we
        // don't have to care about truncating any of the high bits off
        (read_u32_le(&x[x.len() - 64..x.len() - 60]) as usize) & mask
    }

    let len = b.len();

    for chunk in v.chunks_mut(len) {
        copy_memory(b, chunk);
        scrypt_block_mix(chunk, b);
    }

    for _ in 0..n {
        let j = integerify(b, n);
        xor(b, &v[j * len..(j + 1) * len], t);
        scrypt_block_mix(t, b);
    }
}

/// Copy bytes from src to dest
#[inline]
fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    unsafe {
        let srcp = src.as_ptr();
        let dstp = dst.as_mut_ptr();
        ptr::copy_nonoverlapping(srcp, dstp, src.len());
    }
}

#[allow(clippy::uninit_assumed_init)]
fn read_u32_le(input: &[u8]) -> u32 {
    assert_eq!(input.len(), 4);
    unsafe {
        let mut tmp: [u8; 4] = MaybeUninit::uninit().assume_init();
        ptr::copy_nonoverlapping(input.get_unchecked(0), tmp.as_mut_ptr(), 4);
        u32::from_le_bytes(tmp)
    }
}

#[allow(clippy::uninit_assumed_init)]
fn read_u32v_le(dst: &mut [u32], input: &[u8]) {
    assert_eq!(dst.len() * 4, input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: [u8; 4] = MaybeUninit::uninit().assume_init();
            ptr::copy_nonoverlapping(y, tmp.as_mut_ptr(), 4);
            *x = u32::from_le_bytes(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

fn write_u32_le(dst: &mut [u8], mut input: u32) {
    assert_eq!(dst.len(), 4);
    input = input.to_le();
    unsafe {
        let mut tmp = std::mem::transmute::<u32, [u8; 4]>(input);
        ptr::copy_nonoverlapping(tmp.as_mut_ptr(), dst.get_unchecked_mut(0), 4);
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

// Execute the BlockMix operation
// input - the input vector. The length must be a multiple of 128.
// output - the output vector. Must be the same length as input.
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    let mut x = [0u8; 64];
    copy_memory(&input[input.len() - 64..], &mut x);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);
        salsa20_8(&t, &mut x);
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };
        copy_memory(&x, &mut output[pos..pos + 64]);
    }
}

// The salsa20/8 core function.
fn salsa20_8(input: &[u8], output: &mut [u8]) {
    let mut x = [0u32; 16];
    read_u32v_le(&mut x, input);

    let rounds = 8;

    macro_rules! run_round (
        ($($set_idx:expr, $idx_a:expr, $idx_b:expr, $rot:expr);*) => { {
            $( x[$set_idx] ^= x[$idx_a].wrapping_add(x[$idx_b]).rotate_left($rot); )*
        } }
    );

    for _ in 0..rounds / 2 {
        run_round!(
            0x4, 0x0, 0xc, 7;
            0x8, 0x4, 0x0, 9;
            0xc, 0x8, 0x4, 13;
            0x0, 0xc, 0x8, 18;
            0x9, 0x5, 0x1, 7;
            0xd, 0x9, 0x5, 9;
            0x1, 0xd, 0x9, 13;
            0x5, 0x1, 0xd, 18;
            0xe, 0xa, 0x6, 7;
            0x2, 0xe, 0xa, 9;
            0x6, 0x2, 0xe, 13;
            0xa, 0x6, 0x2, 18;
            0x3, 0xf, 0xb, 7;
            0x7, 0x3, 0xf, 9;
            0xb, 0x7, 0x3, 13;
            0xf, 0xb, 0x7, 18;
            0x1, 0x0, 0x3, 7;
            0x2, 0x1, 0x0, 9;
            0x3, 0x2, 0x1, 13;
            0x0, 0x3, 0x2, 18;
            0x6, 0x5, 0x4, 7;
            0x7, 0x6, 0x5, 9;
            0x4, 0x7, 0x6, 13;
            0x5, 0x4, 0x7, 18;
            0xb, 0xa, 0x9, 7;
            0x8, 0xb, 0xa, 9;
            0x9, 0x8, 0xb, 13;
            0xa, 0x9, 0x8, 18;
            0xc, 0xf, 0xe, 7;
            0xd, 0xc, 0xf, 9;
            0xe, 0xd, 0xc, 13;
            0xf, 0xe, 0xd, 18
        )
    }

    for i in 0..16 {
        write_u32_le(
            &mut output[i * 4..(i + 1) * 4],
            x[i].wrapping_add(read_u32_le(&input[i * 4..(i + 1) * 4])),
        );
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_scrypt_ring() {
        let salt = "JhxtHB7UcsDbA9wMSyMKXUzBZUQvqVyB32KwzS9SWoLkjrUhHV".as_bytes();
        let password = "JhxtHB7UcsDbA9wMSyMKXUzBZUQvqVyB32KwzS9SWoLkjrUhHV_".as_bytes();

        let mut seed = [0u8; 32];
        let now = std::time::Instant::now();
        scrypt(
            password,
            salt,
            &params::ScryptParams::default(),
            seed.as_mut(),
        );
        println!("{} ms", now.elapsed().as_millis());

        assert_eq!(
            seed,
            [
                144u8, 5, 70, 118, 105, 47, 173, 220, 39, 152, 105, 7, 211, 34, 125, 146, 183, 172,
                41, 54, 154, 134, 125, 97, 1, 125, 241, 95, 96, 6, 79, 150
            ]
        );
    }
}
