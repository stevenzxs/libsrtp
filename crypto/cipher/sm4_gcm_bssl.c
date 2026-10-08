/* SM4-GCM cipher adapter for BoringSSL-backed libSRTP. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/aead.h>
#include <openssl/sm4.h>

#include <string.h>

#include "alloc.h"
#include "crypto_types.h"
#include "datatypes.h"
#include "err.h"
#include "cipher_types.h"
#include "sm4_gcm.h"

#define SM4_GCM_KEY_LEN 16
#define SM4_GCM_SALT_LEN 12
#define SM4_GCM_TAG_LEN 16
#define SM4_GCM_MAX_AAD_LEN 2048

typedef struct {
    EVP_AEAD_CTX *ctx;
    uint8_t iv[SM4_GCM_SALT_LEN];
    uint8_t aad[SM4_GCM_MAX_AAD_LEN];
    uint8_t tag[SM4_GCM_TAG_LEN];
    size_t aad_len;
    size_t tag_len;
} srtp_sm4_gcm_ctx_t;

static srtp_err_status_t sm4_gcm_alloc(srtp_cipher_t **cp, int key_len,
                                        int tag_len) {
    if (key_len != SM4_GCM_KEY_LEN + SM4_GCM_SALT_LEN ||
        tag_len != SM4_GCM_TAG_LEN) {
        return srtp_err_status_bad_param;
    }

    srtp_cipher_t *c = srtp_crypto_alloc(sizeof(*c));
    srtp_sm4_gcm_ctx_t *state = srtp_crypto_alloc(sizeof(*state));
    if (c == NULL || state == NULL) {
        srtp_crypto_free(c);
        srtp_crypto_free(state);
        return srtp_err_status_alloc_fail;
    }

    state->ctx = NULL;
    state->tag_len = SM4_GCM_TAG_LEN;
    c->state = state;
    c->type = &srtp_sm4_gcm;
    c->algorithm = SRTP_SM4_GCM;
    c->key_len = key_len;
    *cp = c;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_dealloc(srtp_cipher_t *c) {
    if (c != NULL) {
        srtp_sm4_gcm_ctx_t *state = c->state;
        if (state != NULL) {
            EVP_AEAD_CTX_free(state->ctx);
            memset(state, 0, sizeof(*state));
            srtp_crypto_free(state);
        }
        srtp_crypto_free(c);
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_init(void *cv, const uint8_t *key) {
    srtp_sm4_gcm_ctx_t *state = cv;
    EVP_AEAD_CTX_free(state->ctx);
    state->ctx = EVP_AEAD_CTX_new(EVP_aead_sm4_gcm(), key, SM4_GCM_KEY_LEN,
                                  SM4_GCM_TAG_LEN);
    return state->ctx == NULL ? srtp_err_status_init_fail
                              : srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_set_iv(void *cv, uint8_t *iv,
                                         srtp_cipher_direction_t direction) {
    (void)direction;
    srtp_sm4_gcm_ctx_t *state = cv;
    memcpy(state->iv, iv, sizeof(state->iv));
    /* A new packet begins here: reset AAD accumulation. */
    state->aad_len = 0;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_set_aad(void *cv, const uint8_t *aad,
                                          uint32_t aad_len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    /* srtp.c feeds AAD in pieces (e.g. RTCP header then SRTCP trailer), so
     * append instead of overwriting. */
    if (aad_len > sizeof(state->aad) - state->aad_len) {
        return srtp_err_status_bad_param;
    }
    memcpy(state->aad + state->aad_len, aad, aad_len);
    state->aad_len += aad_len;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_encrypt(void *cv, uint8_t *buf,
                                          unsigned int *len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    size_t tag_len = 0;
    uint8_t *out = buf;
    if (*len != 0) {
        out = srtp_crypto_alloc(*len);
        if (out == NULL) {
            return srtp_err_status_alloc_fail;
        }
    }
    if (state->ctx == NULL ||
        !EVP_AEAD_CTX_seal_scatter(
            state->ctx, out, state->tag, &tag_len, sizeof(state->tag), state->iv,
            sizeof(state->iv), buf, *len, NULL, 0, state->aad,
            state->aad_len) ||
        tag_len != state->tag_len) {
        if (out != buf) {
            srtp_crypto_free(out);
        }
        return srtp_err_status_algo_fail;
    }
    if (out != buf) {
        memcpy(buf, out, *len);
        srtp_crypto_free(out);
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_decrypt(void *cv, uint8_t *buf,
                                          unsigned int *len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    size_t out_len = 0;
    if (state->ctx == NULL || *len < state->tag_len ||
        !EVP_AEAD_CTX_open(state->ctx, buf, &out_len, *len, state->iv,
                           sizeof(state->iv), buf, *len, state->aad,
                           state->aad_len) ||
        out_len != *len - state->tag_len) {
        return srtp_err_status_auth_fail;
    }
    *len = (unsigned int)out_len;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_get_tag(void *cv, uint8_t *tag,
                                          uint32_t *len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    memcpy(tag, state->tag, state->tag_len);
    *len = (uint32_t)state->tag_len;
    return srtp_err_status_ok;
}

static const uint8_t sm4_gcm_test_key[SRTP_SM4_GCM_KEY_LEN_WSALT] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
static const uint8_t sm4_gcm_test_iv[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
};
static const uint8_t sm4_gcm_test_aad[] = "rtp-header";
static const uint8_t sm4_gcm_test_plaintext[] = "SM4-SRTP prototype payload";
static const uint8_t sm4_gcm_test_ciphertext[] = {
    0xc4, 0x0b, 0xea, 0xd6, 0x9a, 0x38, 0xd1, 0x50,
    0xdf, 0xec, 0x06, 0x22, 0xa5, 0xd4, 0x8d, 0x1f,
    0x51, 0xf2, 0x21, 0xbb, 0x50, 0x70, 0x79, 0x98,
    0x96, 0x8c, 0xb5, 0x44, 0x50, 0x3c, 0xdb, 0x8e,
    0x00, 0x36, 0x2c, 0xd2, 0x27, 0x08, 0xaf, 0x6b,
    0xf3, 0xbf
};

static const srtp_cipher_test_case_t srtp_sm4_gcm_test_0 = {
    SRTP_SM4_GCM_KEY_LEN_WSALT,
    sm4_gcm_test_key,
    (uint8_t *)sm4_gcm_test_iv,
    sizeof(sm4_gcm_test_plaintext) - 1,
    sm4_gcm_test_plaintext,
    sizeof(sm4_gcm_test_ciphertext),
    sm4_gcm_test_ciphertext,
    sizeof(sm4_gcm_test_aad) - 1,
    sm4_gcm_test_aad,
    SM4_GCM_TAG_LEN,
    NULL
};

const srtp_cipher_type_t srtp_sm4_gcm = {
    sm4_gcm_alloc,     sm4_gcm_dealloc, sm4_gcm_init,   sm4_gcm_set_aad,
    sm4_gcm_encrypt,   sm4_gcm_decrypt, sm4_gcm_set_iv, sm4_gcm_get_tag,
    "SM4-GCM using BoringSSL", &srtp_sm4_gcm_test_0, SRTP_SM4_GCM};

typedef struct {
    SM4_KEY key;
    uint8_t counter[SM4_BLOCK_SIZE];
    uint8_t offset[SM4_BLOCK_SIZE];
} srtp_sm4_ctr_ctx_t;

static const uint8_t sm4_ctr_test_key[SRTP_SM4_GCM_KEY_LEN_WSALT] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
static const uint8_t sm4_ctr_test_iv[SM4_BLOCK_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const uint8_t sm4_ctr_test_plaintext[SM4_BLOCK_SIZE] = { 0 };
static const uint8_t sm4_ctr_test_ciphertext[SM4_BLOCK_SIZE] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

static const srtp_cipher_test_case_t srtp_sm4_ctr_test_0 = {
    SRTP_SM4_GCM_KEY_LEN_WSALT,
    sm4_ctr_test_key,
    (uint8_t *)sm4_ctr_test_iv,
    sizeof(sm4_ctr_test_plaintext),
    sm4_ctr_test_plaintext,
    sizeof(sm4_ctr_test_ciphertext),
    sm4_ctr_test_ciphertext,
    0,
    NULL,
    0,
    NULL
};

static srtp_err_status_t sm4_ctr_alloc(srtp_cipher_t **cp, int key_len,
                                       int tag_len) {
    (void)tag_len;
    if (key_len != SRTP_SM4_GCM_KEY_LEN_WSALT) {
        return srtp_err_status_bad_param;
    }

    srtp_cipher_t *c = srtp_crypto_alloc(sizeof(*c));
    srtp_sm4_ctr_ctx_t *state = srtp_crypto_alloc(sizeof(*state));
    if (c == NULL || state == NULL) {
        srtp_crypto_free(c);
        srtp_crypto_free(state);
        return srtp_err_status_alloc_fail;
    }

    c->state = state;
    c->type = &srtp_sm4_ctr;
    c->algorithm = SRTP_SM4_CTR;
    c->key_len = key_len;
    *cp = c;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_ctr_dealloc(srtp_cipher_t *c) {
    if (c != NULL) {
        srtp_sm4_ctr_ctx_t *state = c->state;
        if (state != NULL) {
            memset(state, 0, sizeof(*state));
            srtp_crypto_free(state);
        }
        srtp_crypto_free(c);
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_ctr_init(void *cv, const uint8_t *key) {
    srtp_sm4_ctr_ctx_t *state = cv;
    if (SM4_set_key(key, &state->key) != 0) {
        return srtp_err_status_init_fail;
    }

    memset(state->offset, 0, sizeof(state->offset));
    memcpy(state->offset, key + SM4_GCM_KEY_LEN,
           SM4_GCM_SALT_LEN);
    state->offset[SM4_GCM_SALT_LEN] = 0;
    state->offset[SM4_GCM_SALT_LEN + 1] = 0;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_ctr_set_iv(void *cv, uint8_t *iv,
                                        srtp_cipher_direction_t direction) {
    (void)direction;
    srtp_sm4_ctr_ctx_t *state = cv;
    unsigned int i;

    for (i = 0; i < SM4_BLOCK_SIZE; ++i) {
        state->counter[i] = iv[i] ^ state->offset[i];
    }
    return srtp_err_status_ok;
}

static void sm4_ctr_increment(uint8_t iv[SM4_BLOCK_SIZE]) {
    int i;
    for (i = SM4_BLOCK_SIZE - 1; i >= 0; --i) {
        if (++iv[i] != 0) {
            break;
        }
    }
}

static srtp_err_status_t sm4_ctr_process(void *cv, uint8_t *buf,
                                         unsigned int *len) {
    srtp_sm4_ctr_ctx_t *state = cv;
    uint8_t keystream[SM4_BLOCK_SIZE];
    unsigned int i;

    for (i = 0; i < *len; ++i) {
        if ((i % SM4_BLOCK_SIZE) == 0) {
            SM4_encrypt(state->counter, keystream, &state->key);
        }
        buf[i] ^= keystream[i % SM4_BLOCK_SIZE];
        if ((i % SM4_BLOCK_SIZE) == (SM4_BLOCK_SIZE - 1)) {
            sm4_ctr_increment(state->counter);
        }
    }

    return srtp_err_status_ok;
}

const srtp_cipher_type_t srtp_sm4_ctr = {
    sm4_ctr_alloc,     sm4_ctr_dealloc, sm4_ctr_init,   0,
    sm4_ctr_process,   sm4_ctr_process, sm4_ctr_set_iv, 0,
    "SM4-CTR using BoringSSL", &srtp_sm4_ctr_test_0, SRTP_SM4_CTR};
