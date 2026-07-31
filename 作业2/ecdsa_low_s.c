#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>

static const unsigned char SECP256K1_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6,
    0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C,
    0xD0, 0x36, 0x41, 0x41
};

/* 以十六进制形式输出字节数组。 */
static void print_hex(
    const char *label,
    const unsigned char *data,
    size_t length
) {
    size_t i;

    printf("%s", label);

    for (i = 0; i < length; ++i) {
        printf("%02X", data[i]);
    }

    putchar('\n');
}


static int subtract_be_32(
    unsigned char out[32],
    const unsigned char a[32],
    const unsigned char b[32]
) {
    int i;
    int borrow = 0;

    for (i = 31; i >= 0; --i) {
        int difference = (int)a[i] - (int)b[i] - borrow;

        if (difference < 0) {
            difference += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }

        out[i] = (unsigned char)difference;
    }

    return borrow == 0;
}

int main(void) {
    secp256k1_context *ctx = NULL;
    secp256k1_pubkey pubkey;

    secp256k1_ecdsa_signature original_sig;
    secp256k1_ecdsa_signature high_s_sig;
    secp256k1_ecdsa_signature normalized_sig;

    unsigned char seckey[32] = {0};

    unsigned char msg_hash[32] = {
        0x7A, 0x21, 0x43, 0x8F,
        0xC5, 0x92, 0x61, 0x16,
        0xFA, 0xD3, 0x0C, 0x57,
        0xA8, 0x10, 0xE4, 0x5B,
        0x91, 0x37, 0xCD, 0x28,
        0x6E, 0x40, 0xB2, 0x75,
        0x19, 0xA6, 0xF8, 0x03,
        0xD4, 0x55, 0xBC, 0x9E
    };

    unsigned char original_compact[64];
    unsigned char high_compact[64];
    unsigned char normalized_compact[64];
    unsigned char high_s[32];

    int original_verify;
    int high_s_verify;
    int normalization_changed;
    int normalized_verify;
    int normalized_equals_original;

    /* 将私钥设置为整数1。 */
    seckey[31] = 0x01;

    printf("============================================================\n");
    printf(" libsecp256k1 ECDSA Low-S Normalization Demonstration\n");
    printf("============================================================\n\n");

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (ctx == NULL) {
        fprintf(stderr, "[ERROR] Failed to create secp256k1 context.\n");
        return EXIT_FAILURE;
    }

    /* 检查固定私钥是否合法。 */
    if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
        fprintf(stderr, "[ERROR] Secret key is invalid.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    /* 根据私钥计算公钥 P = dG。 */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        fprintf(stderr, "[ERROR] Failed to create public key.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    /* 使用固定消息哈希生成正常ECDSA签名。 */
    if (!secp256k1_ecdsa_sign(
            ctx,
            &original_sig,
            msg_hash,
            seckey,
            NULL,
            NULL
        )) {
        fprintf(stderr, "[ERROR] Failed to create ECDSA signature.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    /*
     * 把原始签名序列化为64字节紧凑格式，
     * 便于提取和修改其中的s值。
     */
    if (!secp256k1_ecdsa_signature_serialize_compact(
            ctx,
            original_compact,
            &original_sig
        )) {
        fprintf(stderr, "[ERROR] Failed to serialize signature.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    /* 验证原始低s签名。 */
    original_verify = secp256k1_ecdsa_verify(
        ctx,
        &original_sig,
        msg_hash,
        &pubkey
    );

    memcpy(high_compact, original_compact, sizeof(high_compact));

    if (!subtract_be_32(
            high_s,
            SECP256K1_ORDER,
            original_compact + 32
        )) {
        fprintf(stderr, "[ERROR] Failed to calculate n - s.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    memcpy(high_compact + 32, high_s, 32);

    if (!secp256k1_ecdsa_signature_parse_compact(
            ctx,
            &high_s_sig,
            high_compact
        )) {
        fprintf(stderr, "[ERROR] Failed to parse high-S signature.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    high_s_verify = secp256k1_ecdsa_verify(
        ctx,
        &high_s_sig,
        msg_hash,
        &pubkey
    );

    normalization_changed =
        secp256k1_ecdsa_signature_normalize(
            ctx,
            &normalized_sig,
            &high_s_sig
        );

    /* 验证规范化后的低s签名。 */
    normalized_verify = secp256k1_ecdsa_verify(
        ctx,
        &normalized_sig,
        msg_hash,
        &pubkey
    );

    if (!secp256k1_ecdsa_signature_serialize_compact(
            ctx,
            normalized_compact,
            &normalized_sig
        )) {
        fprintf(stderr, "[ERROR] Failed to serialize normalized signature.\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    normalized_equals_original =
        memcmp(
            original_compact,
            normalized_compact,
            sizeof(original_compact)
        ) == 0;

    printf("[Signature values]\n");
    print_hex("Message hash : ", msg_hash, 32);
    print_hex("R            : ", original_compact, 32);
    print_hex("Original S   : ", original_compact + 32, 32);
    print_hex("High S = n-S : ", high_compact + 32, 32);
    print_hex("Normalized S : ", normalized_compact + 32, 32);

    printf("\n[Verification results]\n");
    printf("[1] Original low-S signature verification : %s\n",
           original_verify ? "PASS" : "FAIL");

    printf("[2] High-S signature construction          : SUCCESS\n");

    printf("[3] High-S signature verification          : %s\n",
           high_s_verify
               ? "ACCEPTED (unexpected)"
               : "REJECTED (expected)");

    printf("[4] Normalization changed the signature    : %s\n",
           normalization_changed ? "YES" : "NO");

    printf("[5] Normalized signature verification      : %s\n",
           normalized_verify ? "PASS" : "FAIL");

    printf("[6] Normalized signature equals original   : %s\n",
           normalized_equals_original ? "YES" : "NO");

    printf("\n[Conclusion]\n");

    if (original_verify &&
        !high_s_verify &&
        normalization_changed &&
        normalized_verify &&
        normalized_equals_original) {

        printf("The experiment completed successfully.\n");
        printf("libsecp256k1 rejected the malleable high-S signature,\n");
        printf("and accepted it again after low-S normalization.\n");

        secp256k1_context_destroy(ctx);
        return EXIT_SUCCESS;
    }

    printf("The experimental result was not as expected.\n");

    secp256k1_context_destroy(ctx);
    return EXIT_FAILURE;
}