////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017, MINRES Technologies GmbH
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
//       eyck@minres.com - initial API and implementation
////////////////////////////////////////////////////////////////////////////////

#include "fp_functions.h"
#include "softfloat_types.h"
#include <array>
#include <cstdint>

extern "C" {
#include "internals.h"
#include "specialize.h"
#include <softfloat.h>
}

#include <limits>

using this_t = uint8_t*;

extern "C" {

uint32_t fget_flags() { return softfloat_exceptionFlags & 0x1f; }
uint16_t fadd_h(uint16_t v1, uint16_t v2, uint8_t mode) {
    float16_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t r = f16_add(v1f, v2f);
    return r.v;
}

uint16_t fsub_h(uint16_t v1, uint16_t v2, uint8_t mode) {
    float16_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t r = f16_sub(v1f, v2f);
    return r.v;
}

uint16_t fmul_h(uint16_t v1, uint16_t v2, uint8_t mode) {
    float16_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t r = f16_mul(v1f, v2f);
    return r.v;
}

uint16_t fdiv_h(uint16_t v1, uint16_t v2, uint8_t mode) {
    float16_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t r = f16_div(v1f, v2f);
    return r.v;
}

uint16_t fsqrt_h(uint16_t v1, uint8_t mode) {
    float16_t v1f{v1};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t r = f16_sqrt(v1f);
    return r.v;
}

uint16_t fcmp_h(uint16_t v1, uint16_t v2, uint16_t op) {
    float16_t v1f{v1}, v2f{v2};
    softfloat_exceptionFlags = 0;
    bool nan = v1 == defaultNaNF16UI || v2 & defaultNaNF16UI;
    bool snan = softfloat_isSigNaNF16UI(v1) || softfloat_isSigNaNF16UI(v2);
    switch(op) {
    case 0:
        if(nan | snan) {
            if(snan)
                softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f16_eq(v1f, v2f) ? 1 : 0;
    case 1:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f16_le(v1f, v2f) ? 1 : 0;
    case 2:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f16_lt(v1f, v2f) ? 1 : 0;
    default:
        break;
    }
    return -1;
}

uint16_t fmadd_h(uint16_t v1, uint16_t v2, uint16_t v3, uint16_t op, uint8_t mode) {
    uint16_t F16_SIGN = 1UL << 15;
    switch(op) {
    case 0: // FMADD_S
        break;
    case 1: // FMSUB_S
        v3 ^= F16_SIGN;
        break;
    case 2: // FNMADD_S
        v1 ^= F16_SIGN;
        v3 ^= F16_SIGN;
        break;
    case 3: // FNMSUB_S
        v1 ^= F16_SIGN;
        break;
    }
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float16_t res = softfloat_mulAddF16(v1, v2, v3, 0);
    return res.v;
}

uint16_t fsel_h(uint16_t v1, uint16_t v2, uint16_t op) {
    softfloat_exceptionFlags = 0;
    bool v1_nan = (v1 & defaultNaNF16UI) == defaultNaNF16UI;
    bool v2_nan = (v2 & defaultNaNF16UI) == defaultNaNF16UI;
    bool v1_snan = softfloat_isSigNaNF16UI(v1);
    bool v2_snan = softfloat_isSigNaNF16UI(v2);
    if(v1_snan || v2_snan)
        softfloat_raiseFlags(softfloat_flag_invalid);
    if(v1_nan || v1_snan)
        return (v2_nan || v2_snan) ? defaultNaNF16UI : v2;
    else if(v2_nan || v2_snan)
        return v1;
    else {
        if((v1 & 0x7fff) == 0 && (v2 & 0x7fff) == 0) {
            return op == 0 ? ((v1 & 0x8000) ? v1 : v2) : ((v1 & 0x8000) ? v2 : v1);
        } else {
            float16_t v1f{v1}, v2f{v2};
            return op == 0 ? (f16_lt(v1f, v2f) ? v1 : v2) : (f16_lt(v1f, v2f) ? v2 : v1);
        }
    }
}

uint16_t fclass_h(uint16_t v1) { return f16_classify(float16_t{v1}); }

uint16_t frsqrt7_h(uint16_t v) { return f16_rsqrte7(float16_t{v}).v; }

uint16_t frec7_h(uint16_t v, uint8_t mode) {
    softfloat_roundingMode = mode;
    return f16_recip7(float16_t{v}).v;
}

uint16_t unbox_h(uint8_t FLEN, uint64_t v) {
    uint64_t mask = 0;
    switch(FLEN) {
    case 32: {
        mask = std::numeric_limits<uint32_t>::max() & ~((uint64_t)std::numeric_limits<uint16_t>::max());
        break;
    }
    case 64: {
        mask = std::numeric_limits<uint64_t>::max() & ~((uint64_t)std::numeric_limits<uint16_t>::max());
        break;
    }
    default:
        break;
    }
    if((v & mask) != mask)
        return defaultNaNF16UI;
    else
        return v & std::numeric_limits<uint32_t>::max();
}

uint32_t fadd_s(uint32_t v1, uint32_t v2, uint8_t mode) {
    float32_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t r = f32_add(v1f, v2f);
    return r.v;
}

uint32_t fsub_s(uint32_t v1, uint32_t v2, uint8_t mode) {
    float32_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t r = f32_sub(v1f, v2f);
    return r.v;
}

uint32_t fmul_s(uint32_t v1, uint32_t v2, uint8_t mode) {
    float32_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t r = f32_mul(v1f, v2f);
    return r.v;
}

uint32_t fdiv_s(uint32_t v1, uint32_t v2, uint8_t mode) {
    float32_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t r = f32_div(v1f, v2f);
    return r.v;
}

uint32_t fsqrt_s(uint32_t v1, uint8_t mode) {
    float32_t v1f{v1};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t r = f32_sqrt(v1f);
    return r.v;
}

uint32_t fcmp_s(uint32_t v1, uint32_t v2, uint32_t op) {
    float32_t v1f{v1}, v2f{v2};
    softfloat_exceptionFlags = 0;
    bool nan = v1 == defaultNaNF32UI || v2 == defaultNaNF32UI;
    bool snan = softfloat_isSigNaNF32UI(v1) || softfloat_isSigNaNF32UI(v2);
    switch(op) {
    case 0:
        if(nan | snan) {
            if(snan)
                softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f32_eq(v1f, v2f) ? 1 : 0;
    case 1:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f32_le(v1f, v2f) ? 1 : 0;
    case 2:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f32_lt(v1f, v2f) ? 1 : 0;
    default:
        break;
    }
    return -1;
}

uint32_t fmadd_s(uint32_t v1, uint32_t v2, uint32_t v3, uint32_t op, uint8_t mode) {
    uint32_t F32_SIGN = 1UL << 31;
    switch(op) {
    case 0: // FMADD_S
        break;
    case 1: // FMSUB_S
        v3 ^= F32_SIGN;
        break;
    case 2: // FNMADD_S
        v1 ^= F32_SIGN;
        v3 ^= F32_SIGN;
        break;
    case 3: // FNMSUB_S
        v1 ^= F32_SIGN;
        break;
    }
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float32_t res = softfloat_mulAddF32(v1, v2, v3, 0);
    return res.v;
}

uint32_t fsel_s(uint32_t v1, uint32_t v2, uint32_t op) {
    softfloat_exceptionFlags = 0;
    bool v1_nan = (v1 & defaultNaNF32UI) == defaultNaNF32UI;
    bool v2_nan = (v2 & defaultNaNF32UI) == defaultNaNF32UI;
    bool v1_snan = softfloat_isSigNaNF32UI(v1);
    bool v2_snan = softfloat_isSigNaNF32UI(v2);
    if(v1_snan || v2_snan)
        softfloat_raiseFlags(softfloat_flag_invalid);
    if(v1_nan || v1_snan)
        return (v2_nan || v2_snan) ? defaultNaNF32UI : v2;
    else if(v2_nan || v2_snan)
        return v1;
    else {
        if((v1 & 0x7fffffff) == 0 && (v2 & 0x7fffffff) == 0) {
            return op == 0 ? ((v1 & 0x80000000) ? v1 : v2) : ((v1 & 0x80000000) ? v2 : v1);
        } else {
            float32_t v1f{v1}, v2f{v2};
            return op == 0 ? (f32_lt(v1f, v2f) ? v1 : v2) : (f32_lt(v1f, v2f) ? v2 : v1);
        }
    }
}

uint32_t fclass_s(uint32_t v1) { return f32_classify(float32_t{v1}); }

uint32_t frsqrt7_s(uint32_t v) { return f32_rsqrte7(float32_t{v}).v; }

uint32_t frec7_s(uint32_t v, uint8_t mode) {
    softfloat_roundingMode = mode;
    return f32_recip7(float32_t{v}).v;
}

uint32_t unbox_s(uint8_t FLEN, uint64_t v) {
    uint64_t mask = 0;
    switch(FLEN) {
    case 32: {
        return v;
    }
    case 64: {
        mask = std::numeric_limits<uint64_t>::max() & ~((uint64_t)std::numeric_limits<uint32_t>::max());
        break;
    }
    default:
        break;
    }
    if((v & mask) != mask)
        return defaultNaNF32UI;
    else
        return v & std::numeric_limits<uint32_t>::max();
}

uint64_t fadd_d(uint64_t v1, uint64_t v2, uint8_t mode) {
    bool nan = v1 == defaultNaNF32UI;
    bool snan = softfloat_isSigNaNF32UI(v1);
    float64_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t r = f64_add(v1f, v2f);
    return r.v;
}

uint64_t fsub_d(uint64_t v1, uint64_t v2, uint8_t mode) {
    float64_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t r = f64_sub(v1f, v2f);
    return r.v;
}

uint64_t fmul_d(uint64_t v1, uint64_t v2, uint8_t mode) {
    float64_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t r = f64_mul(v1f, v2f);
    return r.v;
}

uint64_t fdiv_d(uint64_t v1, uint64_t v2, uint8_t mode) {
    float64_t v1f{v1}, v2f{v2};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t r = f64_div(v1f, v2f);
    return r.v;
}

uint64_t fsqrt_d(uint64_t v1, uint8_t mode) {
    float64_t v1f{v1};
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t r = f64_sqrt(v1f);
    return r.v;
}

uint64_t fcmp_d(uint64_t v1, uint64_t v2, uint32_t op) {
    float64_t v1f{v1}, v2f{v2};
    softfloat_exceptionFlags = 0;
    bool nan = v1 == defaultNaNF64UI || v2 == defaultNaNF64UI;
    bool snan = softfloat_isSigNaNF64UI(v1) || softfloat_isSigNaNF64UI(v2);
    switch(op) {
    case 0:
        if(nan | snan) {
            if(snan)
                softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f64_eq(v1f, v2f) ? 1 : 0;
    case 1:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f64_le(v1f, v2f) ? 1 : 0;
    case 2:
        if(nan | snan) {
            softfloat_raiseFlags(softfloat_flag_invalid);
            return 0;
        } else
            return f64_lt(v1f, v2f) ? 1 : 0;
    default:
        break;
    }
    return -1;
}

uint64_t fmadd_d(uint64_t v1, uint64_t v2, uint64_t v3, uint32_t op, uint8_t mode) {
    uint64_t F64_SIGN = 1ULL << 63;
    switch(op) {
    case 0: // FMADD_D
        break;
    case 1: // FMSUB_D
        v3 ^= F64_SIGN;
        break;
    case 2: // FNMADD_D
        v1 ^= F64_SIGN;
        v3 ^= F64_SIGN;
        break;
    case 3: // FNMSUB_D
        v1 ^= F64_SIGN;
        break;
    }
    softfloat_roundingMode = mode;
    softfloat_exceptionFlags = 0;
    float64_t res = softfloat_mulAddF64(v1, v2, v3, 0);
    return res.v;
}

uint64_t fsel_d(uint64_t v1, uint64_t v2, uint32_t op) {
    softfloat_exceptionFlags = 0;
    bool v1_nan = (v1 & defaultNaNF64UI) == defaultNaNF64UI;
    bool v2_nan = (v2 & defaultNaNF64UI) == defaultNaNF64UI;
    bool v1_snan = softfloat_isSigNaNF64UI(v1);
    bool v2_snan = softfloat_isSigNaNF64UI(v2);
    if(v1_snan || v2_snan)
        softfloat_raiseFlags(softfloat_flag_invalid);
    if(v1_nan || v1_snan)
        return (v2_nan || v2_snan) ? defaultNaNF64UI : v2;
    else if(v2_nan || v2_snan)
        return v1;
    else {
        if((v1 & std::numeric_limits<int64_t>::max()) == 0 && (v2 & std::numeric_limits<int64_t>::max()) == 0) {
            return op == 0 ? ((v1 & std::numeric_limits<int64_t>::min()) ? v1 : v2)
                           : ((v1 & std::numeric_limits<int64_t>::min()) ? v2 : v1);
        } else {
            float64_t v1f{v1}, v2f{v2};
            return op == 0 ? (f64_lt(v1f, v2f) ? v1 : v2) : (f64_lt(v1f, v2f) ? v2 : v1);
        }
    }
}

uint64_t fclass_d(uint64_t v1) { return f64_classify(float64_t{v1}); }

uint64_t frsqrt7_d(uint64_t v) { return f64_rsqrte7(float64_t{v}).v; }

uint64_t frec7_d(uint64_t v, uint8_t mode) {
    softfloat_roundingMode = mode;
    return f64_recip7(float64_t{v}).v;
}

uint64_t unbox_d(uint8_t FLEN, uint64_t v) {
    uint64_t mask = 0;
    switch(FLEN) {
    case 64: {
        return v;
        break;
    }
    default:
        break;
    }
    if((v & mask) != mask)
        return defaultNaNF64UI;
    else
        return v & std::numeric_limits<uint32_t>::max();
}

// conversion: float to float
uint32_t f16tof32(uint16_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_f32(float16_t{val}).v;
}
uint64_t f16tof64(uint16_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_f64(float16_t{val}).v;
}

uint16_t f32tof16(uint32_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_f16(float32_t{val}).v;
}
uint64_t f32tof64(uint32_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_f64(float32_t{val}).v;
}

uint16_t f64tof16(uint64_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_f16(float64_t{val}).v;
}
uint32_t f64tof32(uint64_t val, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_f32(float64_t{val}).v;
}

// conversions: float to unsigned
uint32_t f16toui32(uint16_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_ui32(float16_t{v}, rm, true);
}
uint64_t f16toui64(uint16_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_ui64(float16_t{v}, rm, true);
}
uint32_t f32toui32(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_ui32(float32_t{v}, rm, true);
}
uint64_t f32toui64(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_ui64(float32_t{v}, rm, true);
}
uint32_t f64toui32(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_ui32(float64_t{v}, rm, true);
}
uint64_t f64toui64(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_ui64(float64_t{v}, rm, true);
}

// conversions: float to signed
uint32_t f16toi32(uint16_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_i32(float16_t{v}, rm, true);
}
uint64_t f16toi64(uint16_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f16_to_i64(float16_t{v}, rm, true);
}
uint32_t f32toi32(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_i32(float32_t{v}, rm, true);
}
uint64_t f32toi64(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f32_to_i64(float32_t{v}, rm, true);
}
uint32_t f64toi32(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_i32(float64_t{v}, rm, true);
}
uint64_t f64toi64(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return f64_to_i64(float64_t{v}, rm, true);
}

// conversions: unsigned to float
uint16_t ui32tof16(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui32_to_f16(v).v;
}
uint16_t ui64tof16(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui64_to_f16(v).v;
}
uint32_t ui32tof32(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui32_to_f32(v).v;
}
uint32_t ui64tof32(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui64_to_f32(v).v;
}
uint64_t ui32tof64(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui32_to_f64(v).v;
}
uint64_t ui64tof64(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return ui64_to_f64(v).v;
}

// conversions: signed to float
uint16_t i32tof16(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i32_to_f16(v).v;
}
uint16_t i64tof16(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i64_to_f16(v).v;
}
uint32_t i32tof32(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i32_to_f32(v).v;
}
uint32_t i64tof32(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i64_to_f32(v).v;
}
uint64_t i32tof64(uint32_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i32_to_f64(v).v;
}
uint64_t i64tof64(uint64_t v, uint8_t rm) {
    softfloat_exceptionFlags = 0;
    softfloat_roundingMode = rm;
    return i64_to_f64(v).v;
}
}
