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