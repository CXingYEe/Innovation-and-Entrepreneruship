#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES128_RK_WORDS 44

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
    0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
    0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
    0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
    0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
    0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
    0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
    0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
    0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
    0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
    0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
    0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
    0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
    0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
    0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
    0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,
    0x20,0x40,0x80,0x1b,0x36
};

static uint8_t INV_SBOX[256];

static uint32_t TE0[256];
static uint32_t TE1[256];
static uint32_t TE2[256];
static uint32_t TE3[256];

static uint32_t TD0[256];
static uint32_t TD1[256];
static uint32_t TD2[256];
static uint32_t TD3[256];

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;

    while (b != 0) {
        if ((b & 1u) != 0) {
            result ^= a;
        }

        a = xtime(a);
        b >>= 1;
    }

    return result;
}

static uint32_t load_be32(const uint8_t p[4])
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

static void store_be32(uint8_t p[4], uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static uint32_t rot_word(uint32_t x)
{
    return (x << 8) | (x >> 24);
}

static uint32_t sub_word(uint32_t x)
{
    return ((uint32_t)SBOX[(x >> 24) & 0xff] << 24)
         | ((uint32_t)SBOX[(x >> 16) & 0xff] << 16)
         | ((uint32_t)SBOX[(x >> 8) & 0xff] << 8)
         |  (uint32_t)SBOX[x & 0xff];
}

static uint32_t inv_mix_word(uint32_t x)
{
    uint8_t a0 = (uint8_t)(x >> 24);
    uint8_t a1 = (uint8_t)(x >> 16);
    uint8_t a2 = (uint8_t)(x >> 8);
    uint8_t a3 = (uint8_t)x;

    uint8_t b0 =
        gf_mul(a0, 0x0e) ^
        gf_mul(a1, 0x0b) ^
        gf_mul(a2, 0x0d) ^
        gf_mul(a3, 0x09);

    uint8_t b1 =
        gf_mul(a0, 0x09) ^
        gf_mul(a1, 0x0e) ^
        gf_mul(a2, 0x0b) ^
        gf_mul(a3, 0x0d);

    uint8_t b2 =
        gf_mul(a0, 0x0d) ^
        gf_mul(a1, 0x09) ^
        gf_mul(a2, 0x0e) ^
        gf_mul(a3, 0x0b);

    uint8_t b3 =
        gf_mul(a0, 0x0b) ^
        gf_mul(a1, 0x0d) ^
        gf_mul(a2, 0x09) ^
        gf_mul(a3, 0x0e);

    return ((uint32_t)b0 << 24)
         | ((uint32_t)b1 << 16)
         | ((uint32_t)b2 << 8)
         |  (uint32_t)b3;
}

/*
 * 初始化加密和解密T-table。
 * 该初始化只执行一次，不计入后续性能测试。
 */
static void init_ttables(void)
{
    for (int i = 0; i < 256; ++i) {
        INV_SBOX[SBOX[i]] = (uint8_t)i;
    }

    for (int i = 0; i < 256; ++i) {
        uint8_t s = SBOX[i];
        uint8_t s2 = gf_mul(s, 0x02);
        uint8_t s3 = gf_mul(s, 0x03);

        TE0[i] =
            ((uint32_t)s2 << 24) |
            ((uint32_t)s << 16) |
            ((uint32_t)s << 8) |
            s3;

        TE1[i] =
            ((uint32_t)s3 << 24) |
            ((uint32_t)s2 << 16) |
            ((uint32_t)s << 8) |
            s;

        TE2[i] =
            ((uint32_t)s << 24) |
            ((uint32_t)s3 << 16) |
            ((uint32_t)s2 << 8) |
            s;

        TE3[i] =
            ((uint32_t)s << 24) |
            ((uint32_t)s << 16) |
            ((uint32_t)s3 << 8) |
            s2;

        uint8_t is = INV_SBOX[i];
        uint8_t i9 = gf_mul(is, 0x09);
        uint8_t ib = gf_mul(is, 0x0b);
        uint8_t id = gf_mul(is, 0x0d);
        uint8_t ie = gf_mul(is, 0x0e);

        TD0[i] =
            ((uint32_t)ie << 24) |
            ((uint32_t)i9 << 16) |
            ((uint32_t)id << 8) |
            ib;

        TD1[i] =
            ((uint32_t)ib << 24) |
            ((uint32_t)ie << 16) |
            ((uint32_t)i9 << 8) |
            id;

        TD2[i] =
            ((uint32_t)id << 24) |
            ((uint32_t)ib << 16) |
            ((uint32_t)ie << 8) |
            i9;

        TD3[i] =
            ((uint32_t)i9 << 24) |
            ((uint32_t)id << 16) |
            ((uint32_t)ib << 8) |
            ie;
    }
}

static void aes128_key_expand(
    const uint8_t key[16],
    uint32_t round_keys[AES128_RK_WORDS])
{
    for (int i = 0; i < 4; ++i) {
        round_keys[i] = load_be32(key + 4 * i);
    }

    for (int i = 4; i < AES128_RK_WORDS; ++i) {
        uint32_t temp = round_keys[i - 1];

        if ((i % 4) == 0) {
            temp =
                sub_word(rot_word(temp)) ^
                ((uint32_t)RCON[i / 4] << 24);
        }

        round_keys[i] =
            round_keys[i - 4] ^ temp;
    }
}

static void aes128_make_decrypt_keys(
    const uint32_t encrypt_keys[AES128_RK_WORDS],
    uint32_t decrypt_keys[AES128_RK_WORDS])
{
    for (int column = 0; column < 4; ++column) {
        decrypt_keys[column] =
            encrypt_keys[40 + column];
    }

    for (int round = 1; round < 10; ++round) {
        for (int column = 0; column < 4; ++column) {
            decrypt_keys[4 * round + column] =
                inv_mix_word(
                    encrypt_keys[
                        4 * (10 - round) + column
                    ]
                );
        }
    }

    for (int column = 0; column < 4; ++column) {
        decrypt_keys[40 + column] =
            encrypt_keys[column];
    }
}

static void aes128_encrypt_ttable(
    const uint8_t input[16],
    uint8_t output[16],
    const uint32_t round_keys[AES128_RK_WORDS])
{
    uint32_t s0 =
        load_be32(input) ^ round_keys[0];
    uint32_t s1 =
        load_be32(input + 4) ^ round_keys[1];
    uint32_t s2 =
        load_be32(input + 8) ^ round_keys[2];
    uint32_t s3 =
        load_be32(input + 12) ^ round_keys[3];

    for (int round = 1; round < 10; ++round) {
        uint32_t t0 =
            TE0[s0 >> 24] ^
            TE1[(s1 >> 16) & 0xff] ^
            TE2[(s2 >> 8) & 0xff] ^
            TE3[s3 & 0xff] ^
            round_keys[4 * round];

        uint32_t t1 =
            TE0[s1 >> 24] ^
            TE1[(s2 >> 16) & 0xff] ^
            TE2[(s3 >> 8) & 0xff] ^
            TE3[s0 & 0xff] ^
            round_keys[4 * round + 1];

        uint32_t t2 =
            TE0[s2 >> 24] ^
            TE1[(s3 >> 16) & 0xff] ^
            TE2[(s0 >> 8) & 0xff] ^
            TE3[s1 & 0xff] ^
            round_keys[4 * round + 2];

        uint32_t t3 =
            TE0[s3 >> 24] ^
            TE1[(s0 >> 16) & 0xff] ^
            TE2[(s1 >> 8) & 0xff] ^
            TE3[s2 & 0xff] ^
            round_keys[4 * round + 3];

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    uint32_t t0 =
        ((uint32_t)SBOX[s0 >> 24] << 24) |
        ((uint32_t)SBOX[(s1 >> 16) & 0xff] << 16) |
        ((uint32_t)SBOX[(s2 >> 8) & 0xff] << 8) |
        SBOX[s3 & 0xff];

    uint32_t t1 =
        ((uint32_t)SBOX[s1 >> 24] << 24) |
        ((uint32_t)SBOX[(s2 >> 16) & 0xff] << 16) |
        ((uint32_t)SBOX[(s3 >> 8) & 0xff] << 8) |
        SBOX[s0 & 0xff];

    uint32_t t2 =
        ((uint32_t)SBOX[s2 >> 24] << 24) |
        ((uint32_t)SBOX[(s3 >> 16) & 0xff] << 16) |
        ((uint32_t)SBOX[(s0 >> 8) & 0xff] << 8) |
        SBOX[s1 & 0xff];

    uint32_t t3 =
        ((uint32_t)SBOX[s3 >> 24] << 24) |
        ((uint32_t)SBOX[(s0 >> 16) & 0xff] << 16) |
        ((uint32_t)SBOX[(s1 >> 8) & 0xff] << 8) |
        SBOX[s2 & 0xff];

    store_be32(output,      t0 ^ round_keys[40]);
    store_be32(output + 4,  t1 ^ round_keys[41]);
    store_be32(output + 8,  t2 ^ round_keys[42]);
    store_be32(output + 12, t3 ^ round_keys[43]);
}

static void aes128_decrypt_ttable(
    const uint8_t input[16],
    uint8_t output[16],
    const uint32_t round_keys[AES128_RK_WORDS])
{
    uint32_t s0 =
        load_be32(input) ^ round_keys[0];
    uint32_t s1 =
        load_be32(input + 4) ^ round_keys[1];
    uint32_t s2 =
        load_be32(input + 8) ^ round_keys[2];
    uint32_t s3 =
        load_be32(input + 12) ^ round_keys[3];

    for (int round = 1; round < 10; ++round) {
        uint32_t t0 =
            TD0[s0 >> 24] ^
            TD1[(s3 >> 16) & 0xff] ^
            TD2[(s2 >> 8) & 0xff] ^
            TD3[s1 & 0xff] ^
            round_keys[4 * round];

        uint32_t t1 =
            TD0[s1 >> 24] ^
            TD1[(s0 >> 16) & 0xff] ^
            TD2[(s3 >> 8) & 0xff] ^
            TD3[s2 & 0xff] ^
            round_keys[4 * round + 1];

        uint32_t t2 =
            TD0[s2 >> 24] ^
            TD1[(s1 >> 16) & 0xff] ^
            TD2[(s0 >> 8) & 0xff] ^
            TD3[s3 & 0xff] ^
            round_keys[4 * round + 2];

        uint32_t t3 =
            TD0[s3 >> 24] ^
            TD1[(s2 >> 16) & 0xff] ^
            TD2[(s1 >> 8) & 0xff] ^
            TD3[s0 & 0xff] ^
            round_keys[4 * round + 3];

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    uint32_t t0 =
        ((uint32_t)INV_SBOX[s0 >> 24] << 24) |
        ((uint32_t)INV_SBOX[(s3 >> 16) & 0xff] << 16) |
        ((uint32_t)INV_SBOX[(s2 >> 8) & 0xff] << 8) |
        INV_SBOX[s1 & 0xff];

    uint32_t t1 =
        ((uint32_t)INV_SBOX[s1 >> 24] << 24) |
        ((uint32_t)INV_SBOX[(s0 >> 16) & 0xff] << 16) |
        ((uint32_t)INV_SBOX[(s3 >> 8) & 0xff] << 8) |
        INV_SBOX[s2 & 0xff];

    uint32_t t2 =
        ((uint32_t)INV_SBOX[s2 >> 24] << 24) |
        ((uint32_t)INV_SBOX[(s1 >> 16) & 0xff] << 16) |
        ((uint32_t)INV_SBOX[(s0 >> 8) & 0xff] << 8) |
        INV_SBOX[s3 & 0xff];

    uint32_t t3 =
        ((uint32_t)INV_SBOX[s3 >> 24] << 24) |
        ((uint32_t)INV_SBOX[(s2 >> 16) & 0xff] << 16) |
        ((uint32_t)INV_SBOX[(s1 >> 8) & 0xff] << 8) |
        INV_SBOX[s0 & 0xff];

    store_be32(output,      t0 ^ round_keys[40]);
    store_be32(output + 4,  t1 ^ round_keys[41]);
    store_be32(output + 8,  t2 ^ round_keys[42]);
    store_be32(output + 12, t3 ^ round_keys[43]);
}

static void print_hex(
    const char *label,
    const uint8_t *data,
    size_t length)
{
    printf("%-24s", label);

    for (size_t i = 0; i < length; ++i) {
        printf("%02X", data[i]);
    }

    putchar('\n');
}

#ifndef AES_NO_MAIN
int main(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    };

    const uint8_t expected_ciphertext[16] = {
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    };

    uint32_t encrypt_keys[AES128_RK_WORDS];
    uint32_t decrypt_keys[AES128_RK_WORDS];

    uint8_t ciphertext[16];
    uint8_t recovered_plaintext[16];

    init_ttables();

    aes128_key_expand(
        key,
        encrypt_keys
    );

    aes128_make_decrypt_keys(
        encrypt_keys,
        decrypt_keys
    );

    aes128_encrypt_ttable(
        plaintext,
        ciphertext,
        encrypt_keys
    );

    aes128_decrypt_ttable(
        ciphertext,
        recovered_plaintext,
        decrypt_keys
    );

    int encryption_ok =
        memcmp(
            ciphertext,
            expected_ciphertext,
            AES_BLOCK_SIZE
        ) == 0;

    int decryption_ok =
        memcmp(
            recovered_plaintext,
            plaintext,
            AES_BLOCK_SIZE
        ) == 0;

    printf(
        "===== AES-128 T-TABLE IMPLEMENTATION TEST =====\n"
    );

    print_hex("Key:", key, 16);
    print_hex("Plaintext:", plaintext, 16);

    print_hex(
        "Expected ciphertext:",
        expected_ciphertext,
        16
    );

    print_hex(
        "T-table ciphertext:",
        ciphertext,
        16
    );

    print_hex(
        "Recovered plaintext:",
        recovered_plaintext,
        16
    );

    printf("\nT-table generation: SUCCESS\n");

    printf(
        "Encryption KAT: %s\n",
        encryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Decryption KAT: %s\n",
        decryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Overall result: %s\n",
        encryption_ok && decryption_ok
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    return encryption_ok && decryption_ok ? 0 : 1;
}
#endif /* AES_NO_MAIN */
