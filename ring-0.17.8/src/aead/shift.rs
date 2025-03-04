// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::block::{Block, BLOCK_LEN};

#[cfg(target_arch = "x86")]
pub fn shift_full_blocks<F>(in_out: &mut [u8], src: core::ops::RangeFrom<usize>, mut transform: F)
where
    F: FnMut(&[u8; BLOCK_LEN]) -> Block,
{
    let in_out_len = in_out[src.clone()].len();

    for i in (0..in_out_len).step_by(BLOCK_LEN) {
        let block = {
            let input =
                <&[u8; BLOCK_LEN]>::try_from(&in_out[(src.start + i)..][..BLOCK_LEN]).unwrap();
            transform(input)
        };
        let output = <&mut [u8; BLOCK_LEN]>::try_from(&mut in_out[i..][..BLOCK_LEN]).unwrap();
        *output = *block.as_ref();
    }
}

pub fn shift_partial<F>((in_prefix_len, in_out): (usize, &mut [u8]), transform: F)
where
    F: FnOnce(&[u8]) -> Block,
{
    let (block, in_out_len) = {
        let input = &in_out[in_prefix_len..];
        let in_out_len = input.len();
        if in_out_len == 0 {
            return;
        }
        debug_assert!(in_out_len < BLOCK_LEN);
        (transform(input), in_out_len)
    };
    in_out[..in_out_len].copy_from_slice(&block.as_ref()[..in_out_len]);
}


pub fn shift_partial_output<F>((in_prefix_len, in_out, output): (usize, & [u8], &mut [u8]), transform: F)
    where
        F: FnOnce(&[u8]) -> Block,
{
    let (block, in_out_len) = {
        let input = &in_out[in_prefix_len..];
        let in_out_len = input.len();
        if in_out_len == 0 {
            return;
        }
        debug_assert!(in_out_len < BLOCK_LEN);
        (transform(input), in_out_len)
    };
    output[..in_out_len].copy_from_slice(&block.as_ref()[..in_out_len]);
}