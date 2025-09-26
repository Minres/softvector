////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2025, MINRES Technologies GmbH
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Contributors:
//       alex@minres.com - initial API and implementation
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#ifndef _MSC_VER
using int128_t = __int128;
using uint128_t = unsigned __int128;
#endif

uint8_t xt2(uint8_t x);
uint8_t xt3(uint8_t x);
uint8_t gfmul(uint8_t x, uint8_t y);
uint32_t aes_mixcolumn_byte_fwd(uint8_t so);
uint32_t aes_mixcolumn_byte_inv(uint8_t so);
uint32_t aes_mixcolumn_fwd(uint32_t x);
uint32_t aes_mixcolumn_inv(uint32_t x);
uint32_t aes_decode_rcon(uint8_t r);
uint32_t aes_subword_fwd(uint32_t x);
uint32_t aes_subword_inv(uint32_t x);
uint32_t aes_get_column(__uint128_t state, unsigned c);
uint64_t aes_apply_fwd_sbox_to_each_byte(uint64_t x);
uint64_t aes_apply_inv_sbox_to_each_byte(uint64_t x);
uint64_t aes_rv64_shiftrows_fwd(uint64_t rs2, uint64_t rs1);
uint64_t aes_rv64_shiftrows_inv(uint64_t rs2, uint64_t rs1);
uint128_t aes_shift_rows_fwd(uint128_t x);
uint128_t aes_shift_rows_inv(uint128_t x);
uint128_t aes_subbytes_fwd(uint128_t x);
uint128_t aes_subbytes_inv(uint128_t x);
uint128_t aes_mixcolumns_fwd(uint128_t x);
uint128_t aes_mixcolumns_inv(uint128_t x);
uint32_t aes_rotword(uint32_t x);

template <typename T> T rotr(T x, unsigned n) {
    assert(n < sizeof(T) * 8);
    return (x >> n) | (x << (sizeof(T) * 8 - n));
}
template <typename T> T shr(T x, unsigned n) {
    assert(n < sizeof(T) * 8);
    return (x >> n);
}
template <typename T> T sum0(T);
template <> inline uint32_t sum0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
template <> inline uint64_t sum0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
template <typename T> T sum1(T);
template <> inline uint32_t sum1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
template <> inline uint64_t sum1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
template <typename T> T ch(T x, T y, T z) { return ((x & y) ^ ((~x) & z)); }
template <typename T> T maj(T x, T y, T z) { return ((x & y) ^ (x & z) ^ (y & z)); }
template <typename T> T sig0(T);
template <> inline uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
template <> inline uint64_t sig0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7); }
template <typename T> T sig1(T);
template <> inline uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }
template <> inline uint64_t sig1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6); }

template <typename dest_elem_t, typename src_elem_t> dest_elem_t brev(src_elem_t vs2) {
    constexpr dest_elem_t bits = sizeof(src_elem_t) * 8;
    dest_elem_t result = 0;
    for(size_t i = 0; i < bits; ++i) {
        result <<= 1;
        result |= (vs2 & 1);
        vs2 >>= 1;
    }
    return result;
};
template <typename dest_elem_t, typename src_elem_t> dest_elem_t brev8(src_elem_t vs2) {
    constexpr unsigned byte_count = sizeof(src_elem_t);
    dest_elem_t result = 0;
    for(size_t i = 0; i < byte_count; ++i) {
        dest_elem_t byte = (vs2 >> (i * 8)) & 0xFF;
        byte = ((byte & 0xF0) >> 4) | ((byte & 0x0F) << 4);
        byte = ((byte & 0xCC) >> 2) | ((byte & 0x33) << 2);
        byte = ((byte & 0xAA) >> 1) | ((byte & 0x55) << 1);
        result |= byte << (i * 8);
    }
    return result;
};