#ifndef SM3_INTERNAL_H
#define SM3_INTERNAL_H

#include "sm3.h"

static inline uint32_t sm3_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void sm3_store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static inline uint32_t sm3_rol32(uint32_t x, unsigned n)
{
    n &= 31;
    return (x << n) | (x >> ((32 - n) & 31));
}

extern const uint32_t sm3_iv[8];
void sm3_scalar_compress(uint32_t state[8], const uint8_t block[64]);
int sm3_hash_many_avx2(const uint8_t *const data[], size_t count, size_t len,
                       uint8_t out[][SM3_DIGEST_SIZE]);
int sm3_hash_many_avx512(const uint8_t *const data[], size_t count, size_t len,
                         uint8_t out[][SM3_DIGEST_SIZE]);
int sm3_hash_many_neon(const uint8_t *const data[], size_t count, size_t len,
                       uint8_t out[][SM3_DIGEST_SIZE]);

#endif
