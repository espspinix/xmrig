/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "log/Log.h"

#include "crypto/CryptoNight.h"

#if defined(XMRIG_ARM)
#   include "crypto/CryptoNight_arm.h"
#else
#   include "crypto/CryptoNight_x86.h"
#endif

#include "crypto/CryptoNight_test.h"
#include "net/Job.h"
#include "net/JobResult.h"
#include "Options.h"


void (*cryptonight_hash_ctx)(const void *input, size_t size, void *output, cryptonight_ctx *ctx) = nullptr;


static void cryptonight_av1_aesni(const void *input, size_t size, void *output, struct cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}


static void cryptonight_av2_aesni_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_double_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}

static void cryptonight_av5_aesni_triple(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_triple_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}

static void cryptonight_av7_aesni_penta(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_penta_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}


static void cryptonight_av3_softaes(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_hash<0x80000, MEMORY, 0x1FFFF0, true>(input, size, output, ctx);
}


static void cryptonight_av4_softaes_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_double_hash<0x80000, MEMORY, 0x1FFFF0, true>(input, size, output, ctx);
}


#ifndef XMRIG_NO_AEON
static void cryptonight_lite_av1_aesni(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    #   if !defined(XMRIG_ARMv7)
    cryptonight_hash<0x40000, MEMORY_LITE, 0xFFFF0, false>(input, size, output, ctx);
#endif
}


static void cryptonight_lite_av2_aesni_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_double_hash<0x40000, MEMORY_LITE, 0xFFFF0, false>(input, size, output, ctx);
#   endif
}


static void cryptonight_lite_av3_softaes(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_hash<0x40000, MEMORY_LITE, 0xFFFF0, true>(input, size, output, ctx);
}


static void cryptonight_lite_av4_softaes_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_double_hash<0x40000, MEMORY_LITE, 0xFFFF0, true>(input, size, output, ctx);
}

void (*cryptonight_variations[11])(const void *input, size_t size, void *output, cryptonight_ctx *ctx) = {
            cryptonight_av1_aesni,
            cryptonight_av2_aesni_double,
            cryptonight_av3_softaes,
            cryptonight_av4_softaes_double,
            cryptonight_av5_aesni_triple,
            cryptonight_av5_aesni_triple,
            cryptonight_av7_aesni_penta,
            cryptonight_lite_av1_aesni,
            cryptonight_lite_av2_aesni_double,
            cryptonight_lite_av3_softaes,
            cryptonight_lite_av4_softaes_double
        };
#else
void (*cryptonight_variations[7])(const void *input, size_t size, void *output, cryptonight_ctx *ctx) = {
            cryptonight_av1_aesni,
            cryptonight_av2_aesni_double,
            cryptonight_av3_softaes,
            cryptonight_av4_softaes_double,
            cryptonight_av5_aesni_triple,
            cryptonight_av7_aesni_penta,
            cryptonight_av7_aesni_penta
        };
#endif


bool CryptoNight::hash(const Job &job, JobResult &result, cryptonight_ctx *ctx)
{
    cryptonight_hash_ctx(job.blob(), job.size(), result.result, ctx);

    return *reinterpret_cast<uint64_t*>(result.result + 24) < job.target();
}


bool CryptoNight::init(int algo, int variant)
{
    if (variant < 1 || variant > 7) {
        return false;
    }

#   ifndef XMRIG_NO_AEON
    const int index = algo == Options::ALGO_CRYPTONIGHT_LITE ? (variant + 4) : (variant - 1);
#   else
    const int index = variant - 1;
#   endif

    cryptonight_hash_ctx = cryptonight_variations[index];

    return selfTest(algo);
}


void CryptoNight::hash(const uint8_t *input, size_t size, uint8_t *output, cryptonight_ctx *ctx)
{
    cryptonight_hash_ctx(input, size, output, ctx);
}


bool CryptoNight::selfTest(int algo) {
    if (cryptonight_hash_ctx == nullptr) {
        return false;
    }

    int SIZE, RATIO;
    char my_test_input;

    if (Options::i()->doubleHash() == 5) {
        SIZE = 32 * 5;
        RATIO = 5;
    } else if (Options::i()->doubleHash() == 4) {
        SIZE = 32 * 4;
        RATIO = 4;
    } else if (Options::i()->doubleHash() == 3) {
        SIZE = 96;
        RATIO = 3;        
    } else if (Options::i()->doubleHash() == 2) {
        SIZE = 64;
        RATIO = 2;
    } else {
        SIZE = 32;
        RATIO = 1;
    }

    char output[SIZE];

    struct cryptonight_ctx *ctx = (struct cryptonight_ctx*) _mm_malloc(sizeof(struct cryptonight_ctx), 16);
    ctx->memory = (uint8_t *) _mm_malloc(MEMORY * RATIO, 16);

    cryptonight_hash_ctx(my_test_input3, 14, output, ctx);

    _mm_free(ctx->memory);
    _mm_free(ctx);

#   ifndef XMRIG_NO_AEON
    return memcmp(output, algo == Options::ALGO_CRYPTONIGHT_LITE ? test_output1 : my_test_output3, SIZE) == 0;
#   else
    return memcmp(output, my_test_output3, 32) == 0;
#   endif
}
