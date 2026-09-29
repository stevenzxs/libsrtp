/* SM4-GCM cipher adapter for BoringSSL-backed libSRTP. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/aead.h>

#include <string.h>

#include "alloc.h"
#include "cipher_types.h"
#include "crypto_types.h"
#include "err.h"
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
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_set_aad(void *cv, const uint8_t *aad,
                                          uint32_t aad_len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    if (aad_len > sizeof(state->aad)) {
        return srtp_err_status_bad_param;
    }
    memcpy(state->aad, aad, aad_len);
    state->aad_len = aad_len;
    return srtp_err_status_ok;
}

static srtp_err_status_t sm4_gcm_encrypt(void *cv, uint8_t *buf,
                                          unsigned int *len) {
    srtp_sm4_gcm_ctx_t *state = cv;
    size_t tag_len = 0;
    if (state->ctx == NULL ||
        !EVP_AEAD_CTX_seal_scatter(
            state->ctx, buf, state->tag, &tag_len, sizeof(state->tag),
            state->iv, sizeof(state->iv), buf, *len, NULL, 0, state->aad,
            state->aad_len) ||
        tag_len != state->tag_len) {
        return srtp_err_status_algo_fail;
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

const srtp_cipher_type_t srtp_sm4_gcm = {
    sm4_gcm_alloc,     sm4_gcm_dealloc, sm4_gcm_init,   sm4_gcm_set_aad,
    sm4_gcm_encrypt,   sm4_gcm_decrypt, sm4_gcm_set_iv, sm4_gcm_get_tag,
    "SM4-GCM using BoringSSL", NULL, SRTP_SM4_GCM};
