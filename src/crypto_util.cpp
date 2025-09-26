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

#include <array>
#include <cassert>
#include <crypto_util.h>
#include <cstdint>
#include <type_traits>
#ifndef _MSC_VER
using int128_t = __int128;
using uint128_t = unsigned __int128;
#endif
namespace softvector {
template <unsigned int bit, unsigned int width, typename T>
constexpr typename std::enable_if<std::is_unsigned<T>::value, T>::type bit_sub(T v) {
    static_assert((bit + width) <= 8 * sizeof(T));
    T res = (v >> bit) & ((T(1) << width) - 1);
    return res;
}

template <unsigned int bit, unsigned int width, typename T>
constexpr typename std::enable_if<std::is_signed<T>::value, T>::type bit_sub(T v) {
    static_assert((bit + width) <= 8 * sizeof(T));
    static_assert(width > 0);
    auto field = v >> bit;
    auto amount = (field & ~(~T(1) << (width - 1) << 1)) - (field & (T(1) << (width - 1)) << 1);
    return amount;
}
uint8_t xt2(uint8_t x) { return (x << 1) ^ (bit_sub<7, 1>(x) ? 27 : 0); }

uint8_t xt3(uint8_t x) { return x ^ xt2(x); }

uint8_t gfmul(uint8_t x, uint8_t y) {
    return (bit_sub<0, 1>(y) ? x : 0) ^ (bit_sub<1, 1>(y) ? xt2(x) : 0) ^ (bit_sub<2, 1>(y) ? xt2(xt2(x)) : 0) ^
           (bit_sub<3, 1>(y) ? xt2(xt2(xt2(x))) : 0);
}

uint32_t aes_mixcolumn_byte_fwd(uint8_t so) {
    return ((uint32_t)gfmul(so, 3) << 24) | ((uint32_t)so << 16) | ((uint32_t)so << 8) | gfmul(so, 2);
}

uint32_t aes_mixcolumn_byte_inv(uint8_t so) {
    return ((uint32_t)gfmul(so, 11) << 24) | ((uint32_t)gfmul(so, 13) << 16) | ((uint32_t)gfmul(so, 9) << 8) | gfmul(so, 14);
}

uint32_t aes_mixcolumn_fwd(uint32_t x) {
    uint8_t s0 = bit_sub<0, 7 - 0 + 1>(x);
    uint8_t s1 = bit_sub<8, 15 - 8 + 1>(x);
    uint8_t s2 = bit_sub<16, 23 - 16 + 1>(x);
    uint8_t s3 = bit_sub<24, 31 - 24 + 1>(x);
    uint8_t b0 = xt2(s0) ^ xt3(s1) ^ (s2) ^ (s3);
    uint8_t b1 = (s0) ^ xt2(s1) ^ xt3(s2) ^ (s3);
    uint8_t b2 = (s0) ^ (s1) ^ xt2(s2) ^ xt3(s3);
    uint8_t b3 = xt3(s0) ^ (s1) ^ (s2) ^ xt2(s3);
    return ((uint32_t)b3 << 24) | ((uint32_t)b2 << 16) | ((uint32_t)b1 << 8) | b0;
}

uint32_t aes_mixcolumn_inv(uint32_t x) {
    uint8_t s0 = bit_sub<0, 7 - 0 + 1>(x);
    uint8_t s1 = bit_sub<8, 15 - 8 + 1>(x);
    uint8_t s2 = bit_sub<16, 23 - 16 + 1>(x);
    uint8_t s3 = bit_sub<24, 31 - 24 + 1>(x);
    uint8_t b0 = gfmul(s0, 14) ^ gfmul(s1, 11) ^ gfmul(s2, 13) ^ gfmul(s3, 9);
    uint8_t b1 = gfmul(s0, 9) ^ gfmul(s1, 14) ^ gfmul(s2, 11) ^ gfmul(s3, 13);
    uint8_t b2 = gfmul(s0, 13) ^ gfmul(s1, 9) ^ gfmul(s2, 14) ^ gfmul(s3, 11);
    uint8_t b3 = gfmul(s0, 11) ^ gfmul(s1, 13) ^ gfmul(s2, 9) ^ gfmul(s3, 14);
    return ((uint32_t)b3 << 24) | ((uint32_t)b2 << 16) | ((uint32_t)b1 << 8) | b0;
}

uint32_t aes_decode_rcon(uint8_t r) {
    switch(r) {
    case 0:
        return 1;
    case 1:
        return 2;
    case 2:
        return 4;
    case 3:
        return 8;
    case 4:
        return 16;
    case 5:
        return 32;
    case 6:
        return 64;
    case 7:
        return 128;
    case 8:
        return 27;
    case 9:
        return 54;
    }
    return 0;
}
constexpr std::array<uint8_t, 256> AES_ENC_SBOX = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
     0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1,
     0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83,
     0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
     0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
     0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
     0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
     0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
     0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
     0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
     0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1,
     0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

constexpr std::array<uint8_t, 256> AES_DEC_SBOX = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F,
     0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B,
     0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8,
     0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
     0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3,
     0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
     0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9,
     0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
     0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07,
     0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F,
     0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B,
     0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

uint32_t aes_subword_fwd(uint32_t x) {
    return ((uint32_t)AES_ENC_SBOX[bit_sub<24, 31 - 24 + 1>(x)] << 24) | ((uint32_t)AES_ENC_SBOX[bit_sub<16, 23 - 16 + 1>(x)] << 16) |
           ((uint32_t)AES_ENC_SBOX[bit_sub<8, 15 - 8 + 1>(x)] << 8) | AES_ENC_SBOX[bit_sub<0, 7 - 0 + 1>(x)];
}

uint32_t aes_subword_inv(uint32_t x) {
    return ((uint32_t)AES_DEC_SBOX[bit_sub<24, 31 - 24 + 1>(x)] << 24) | ((uint32_t)AES_DEC_SBOX[bit_sub<16, 23 - 16 + 1>(x)] << 16) |
           ((uint32_t)AES_DEC_SBOX[bit_sub<8, 15 - 8 + 1>(x)] << 8) | AES_DEC_SBOX[bit_sub<0, 7 - 0 + 1>(x)];
}

uint32_t aes_get_column(__uint128_t state, unsigned c) {
    assert(c < 4);
    return static_cast<uint32_t>(state >> (32 * c));
};

uint64_t aes_apply_fwd_sbox_to_each_byte(uint64_t x) {
    return ((uint64_t)AES_ENC_SBOX[bit_sub<56, 63 - 56 + 1>(x)] << 56) | ((uint64_t)AES_ENC_SBOX[bit_sub<48, 55 - 48 + 1>(x)] << 48) |
           ((uint64_t)AES_ENC_SBOX[bit_sub<40, 47 - 40 + 1>(x)] << 40) | ((uint64_t)AES_ENC_SBOX[bit_sub<32, 39 - 32 + 1>(x)] << 32) |
           ((uint64_t)AES_ENC_SBOX[bit_sub<24, 31 - 24 + 1>(x)] << 24) | ((uint64_t)AES_ENC_SBOX[bit_sub<16, 23 - 16 + 1>(x)] << 16) |
           ((uint64_t)AES_ENC_SBOX[bit_sub<8, 15 - 8 + 1>(x)] << 8) | AES_ENC_SBOX[bit_sub<0, 7 - 0 + 1>(x)];
}

uint64_t aes_apply_inv_sbox_to_each_byte(uint64_t x) {
    return ((uint64_t)AES_DEC_SBOX[bit_sub<56, 63 - 56 + 1>(x)] << 56) | ((uint64_t)AES_DEC_SBOX[bit_sub<48, 55 - 48 + 1>(x)] << 48) |
           ((uint64_t)AES_DEC_SBOX[bit_sub<40, 47 - 40 + 1>(x)] << 40) | ((uint64_t)AES_DEC_SBOX[bit_sub<32, 39 - 32 + 1>(x)] << 32) |
           ((uint64_t)AES_DEC_SBOX[bit_sub<24, 31 - 24 + 1>(x)] << 24) | ((uint64_t)AES_DEC_SBOX[bit_sub<16, 23 - 16 + 1>(x)] << 16) |
           ((uint64_t)AES_DEC_SBOX[bit_sub<8, 15 - 8 + 1>(x)] << 8) | AES_DEC_SBOX[bit_sub<0, 7 - 0 + 1>(x)];
}

uint64_t aes_rv64_shiftrows_fwd(uint64_t rs2, uint64_t rs1) {
    return ((uint64_t)bit_sub<24, 31 - 24 + 1>(rs1) << 56) | ((uint64_t)bit_sub<48, 55 - 48 + 1>(rs2) << 48) |
           ((uint64_t)bit_sub<8, 15 - 8 + 1>(rs2) << 40) | ((uint64_t)bit_sub<32, 39 - 32 + 1>(rs1) << 32) |
           ((uint64_t)bit_sub<56, 63 - 56 + 1>(rs2) << 24) | ((uint64_t)bit_sub<16, 23 - 16 + 1>(rs2) << 16) |
           ((uint64_t)bit_sub<40, 47 - 40 + 1>(rs1) << 8) | bit_sub<0, 7 - 0 + 1>(rs1);
}

uint64_t aes_rv64_shiftrows_inv(uint64_t rs2, uint64_t rs1) {
    return ((uint64_t)bit_sub<24, 31 - 24 + 1>(rs2) << 56) | ((uint64_t)bit_sub<48, 55 - 48 + 1>(rs2) << 48) |
           ((uint64_t)bit_sub<8, 15 - 8 + 1>(rs1) << 40) | ((uint64_t)bit_sub<32, 39 - 32 + 1>(rs1) << 32) |
           ((uint64_t)bit_sub<56, 63 - 56 + 1>(rs1) << 24) | ((uint64_t)bit_sub<16, 23 - 16 + 1>(rs2) << 16) |
           ((uint64_t)bit_sub<40, 47 - 40 + 1>(rs2) << 8) | bit_sub<0, 7 - 0 + 1>(rs1);
}

uint128_t aes_shift_rows_fwd(uint128_t x) {
    uint32_t ic3 = aes_get_column(x, 3);
    uint32_t ic2 = aes_get_column(x, 2);
    uint32_t ic1 = aes_get_column(x, 1);
    uint32_t ic0 = aes_get_column(x, 0);
    uint32_t oc0 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic3) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic2) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic1) << 8) | bit_sub<0, 7 - 0 + 1>(ic0);
    uint32_t oc1 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic0) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic3) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic2) << 8) | bit_sub<0, 7 - 0 + 1>(ic1);
    uint32_t oc2 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic1) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic0) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic3) << 8) | bit_sub<0, 7 - 0 + 1>(ic2);
    uint32_t oc3 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic2) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic1) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic0) << 8) | bit_sub<0, 7 - 0 + 1>(ic3);
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint128_t aes_shift_rows_inv(uint128_t x) {
    uint32_t ic3 = aes_get_column(x, 3);
    uint32_t ic2 = aes_get_column(x, 2);
    uint32_t ic1 = aes_get_column(x, 1);
    uint32_t ic0 = aes_get_column(x, 0);
    uint32_t oc0 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic1) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic2) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic3) << 8) | bit_sub<0, 7 - 0 + 1>(ic0);
    uint32_t oc1 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic2) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic3) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic0) << 8) | bit_sub<0, 7 - 0 + 1>(ic1);
    uint32_t oc2 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic3) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic0) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic1) << 8) | bit_sub<0, 7 - 0 + 1>(ic2);
    uint32_t oc3 = ((uint32_t)bit_sub<24, 31 - 24 + 1>(ic0) << 24) | ((uint32_t)bit_sub<16, 23 - 16 + 1>(ic1) << 16) |
                   ((uint32_t)bit_sub<8, 15 - 8 + 1>(ic2) << 8) | bit_sub<0, 7 - 0 + 1>(ic3);
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint128_t aes_subbytes_fwd(uint128_t x) {
    uint32_t oc0 = aes_subword_fwd(aes_get_column(x, 0));
    uint32_t oc1 = aes_subword_fwd(aes_get_column(x, 1));
    uint32_t oc2 = aes_subword_fwd(aes_get_column(x, 2));
    uint32_t oc3 = aes_subword_fwd(aes_get_column(x, 3));
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint128_t aes_subbytes_inv(uint128_t x) {
    uint32_t oc0 = aes_subword_inv(aes_get_column(x, 0));
    uint32_t oc1 = aes_subword_inv(aes_get_column(x, 1));
    uint32_t oc2 = aes_subword_inv(aes_get_column(x, 2));
    uint32_t oc3 = aes_subword_inv(aes_get_column(x, 3));
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint128_t aes_mixcolumns_fwd(uint128_t x) {
    uint32_t oc0 = aes_mixcolumn_fwd(aes_get_column(x, 0));
    uint32_t oc1 = aes_mixcolumn_fwd(aes_get_column(x, 1));
    uint32_t oc2 = aes_mixcolumn_fwd(aes_get_column(x, 2));
    uint32_t oc3 = aes_mixcolumn_fwd(aes_get_column(x, 3));
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint128_t aes_mixcolumns_inv(uint128_t x) {
    uint32_t oc0 = aes_mixcolumn_inv(aes_get_column(x, 0));
    uint32_t oc1 = aes_mixcolumn_inv(aes_get_column(x, 1));
    uint32_t oc2 = aes_mixcolumn_inv(aes_get_column(x, 2));
    uint32_t oc3 = aes_mixcolumn_inv(aes_get_column(x, 3));
    return ((uint128_t)oc3 << 96) | ((uint128_t)oc2 << 64) | ((uint128_t)oc1 << 32) | oc0;
}

uint32_t aes_rotword(uint32_t x) {
    uint8_t a0 = bit_sub<0, 7 - 0 + 1>(x);
    uint8_t a1 = bit_sub<8, 15 - 8 + 1>(x);
    uint8_t a2 = bit_sub<16, 23 - 16 + 1>(x);
    uint8_t a3 = bit_sub<24, 31 - 24 + 1>(x);
    return ((uint32_t)a0 << 24) | ((uint32_t)a3 << 16) | ((uint32_t)a2 << 8) | a1;
}
} // namespace softvector