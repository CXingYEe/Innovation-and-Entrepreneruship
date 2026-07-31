#include "sm3_internal.h"
#include <stdlib.h>
#include <string.h>

const uint32_t sm3_iv[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};

void sm3_scalar_compress(uint32_t s[8], const uint8_t block[64])
{
    uint32_t w[68], wp[64];
    uint32_t a=s[0], b=s[1], c=s[2], d=s[3];
    uint32_t e=s[4], f=s[5], g=s[6], h=s[7];
    unsigned j;

    for (j=0; j<16; ++j) w[j] = sm3_load_be32(block + 4*j);
    for (j=16; j<68; ++j) {
        uint32_t x = w[j-16] ^ w[j-9] ^ sm3_rol32(w[j-3], 15);
        w[j] = x ^ sm3_rol32(x, 15) ^ sm3_rol32(x, 23) ^
               sm3_rol32(w[j-13], 7) ^ w[j-6];
    }
    for (j=0; j<64; ++j) wp[j] = w[j] ^ w[j+4];
    for (j=0; j<64; ++j) {
        uint32_t tj = j < 16 ? 0x79cc4519U : 0x7a879d8aU;
        uint32_t ss1 = sm3_rol32(sm3_rol32(a,12) + e + sm3_rol32(tj,j), 7);
        uint32_t ss2 = ss1 ^ sm3_rol32(a,12);
        uint32_t ff = j < 16 ? (a ^ b ^ c) :
                      ((a & b) | (a & c) | (b & c));
        uint32_t gg = j < 16 ? (e ^ f ^ g) :
                      ((e & f) | ((~e) & g));
        uint32_t tt1 = ff + d + ss2 + wp[j];
        uint32_t tt2 = gg + h + ss1 + w[j];
        d=c; c=sm3_rol32(b,9); b=a; a=tt1;
        h=g; g=sm3_rol32(f,19); f=e;
        e=tt2 ^ sm3_rol32(tt2,9) ^ sm3_rol32(tt2,17);
    }
    s[0]^=a; s[1]^=b; s[2]^=c; s[3]^=d;
    s[4]^=e; s[5]^=f; s[6]^=g; s[7]^=h;
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t s[8];
    uint8_t block[128];
    size_t full = len & ~(size_t)63, rem = len - full, pad, i;
    uint64_t bits = (uint64_t)len * 8;
    memcpy(s, sm3_iv, sizeof(s));
    for (i=0; i<full; i+=64) sm3_scalar_compress(s, data+i);
    pad = rem < 56 ? 64 : 128;
    memset(block, 0, pad);
    if (rem) memcpy(block, data+full, rem);
    block[rem] = 0x80;
    for (i=0; i<8; ++i) block[pad-1-i] = (uint8_t)(bits >> (8*i));
    sm3_scalar_compress(s, block);
    if (pad == 128) sm3_scalar_compress(s, block+64);
    for (i=0; i<8; ++i) sm3_store_be32(out+4*i, s[i]);
}

static int scalar_many(const uint8_t *const d[], size_t n, size_t len,
                       uint8_t out[][32])
{
    size_t i;
    for (i=0; i<n; ++i) sm3_hash(d[i], len, out[i]);
    return 0;
}

int sm3_hash_many(sm3_impl impl, const uint8_t *const d[], size_t n,
                  size_t len, uint8_t out[][32])
{
    if (!sm3_impl_available(impl)) return -1;
    switch (impl) {
    case SM3_IMPL_AVX2: return sm3_hash_many_avx2(d,n,len,out);
    case SM3_IMPL_AVX512: return sm3_hash_many_avx512(d,n,len,out);
    case SM3_IMPL_NEON: return sm3_hash_many_neon(d,n,len,out);
    default: return scalar_many(d,n,len,out);
    }
}

const char *sm3_impl_name(sm3_impl impl)
{
    static const char *n[] = {"scalar","avx2","avx512","neon"};
    return (unsigned)impl < 4 ? n[impl] : "unknown";
}

int sm3_impl_available(sm3_impl impl)
{
    if (impl == SM3_IMPL_SCALAR) return 1;
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
    if (impl == SM3_IMPL_AVX2) return __builtin_cpu_supports("avx2") != 0;
    if (impl == SM3_IMPL_AVX512) return __builtin_cpu_supports("avx512f") != 0;
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
    if (impl == SM3_IMPL_NEON) return 1;
#endif
    return 0;
}
