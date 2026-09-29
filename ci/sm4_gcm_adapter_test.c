#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sm4.h>

#include "cipher.h"
#include "sm4_gcm.h"

void *srtp_crypto_alloc(size_t size) { return calloc(1, size); }
void srtp_crypto_free(void *ptr) { free(ptr); }

static const unsigned char key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
static const unsigned char iv[12] = {
    0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd};
static const unsigned char aad[21] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa,
    0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xab, 0xad, 0xda, 0xd2};
static const unsigned char plaintext[64] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
static const unsigned char ciphertext[64] = {
    0x17, 0xf3, 0x99, 0xf0, 0x8c, 0x67, 0xd5, 0xee, 0x19, 0xd0, 0xdc,
    0x99, 0x69, 0xc4, 0xbb, 0x7d, 0x5f, 0xd4, 0x6f, 0xd3, 0x75, 0x64,
    0x89, 0x06, 0x91, 0x57, 0xb2, 0x82, 0xbb, 0x20, 0x07, 0x35, 0xd8,
    0x27, 0x10, 0xca, 0x5c, 0x22, 0xf0, 0xcc, 0xfa, 0x7c, 0xbf, 0x93,
    0xd4, 0x96, 0xac, 0x15, 0xa5, 0x68, 0x34, 0xcb, 0xcf, 0x98, 0xc3,
    0x97, 0xb4, 0x02, 0x4a, 0x26, 0x91, 0x23, 0x3b, 0x8d};
static const unsigned char tag[16] = {
    0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81,
    0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b, 0x62, 0xec};

static int check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "SM4-GCM adapter test failed: %s\n", message);
        return 0;
    }
    return 1;
}

static void dump_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        fprintf(stderr, "%02x", data[i]);
    }
    fputc('\n', stderr);
}

int main(void) {
    unsigned char key_with_salt[28] = {0};
    unsigned char packet[80] = {0};
    unsigned char actual_tag[16] = {0};
    unsigned int packet_len = sizeof(plaintext);
    uint32_t actual_tag_len = 0;
    srtp_cipher_t *cipher = NULL;
    unsigned char direct_ciphertext[sizeof(plaintext)] = {0};
    unsigned char direct_tag[sizeof(tag)] = {0};

    if (!check(SM4_GCM_encrypt(key, iv, aad, sizeof(aad), plaintext,
                               sizeof(plaintext), direct_ciphertext,
                               direct_tag),
               "direct SM4-GCM encrypt")) {
        return 1;
    }
    if (memcmp(direct_ciphertext, ciphertext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "direct ciphertext: ");
        dump_hex(direct_ciphertext, sizeof(direct_ciphertext));
        fprintf(stderr, "expected ciphertext: ");
        dump_hex(ciphertext, sizeof(ciphertext));
        return 1;
    }
    if (memcmp(direct_tag, tag, sizeof(tag)) != 0) {
        fprintf(stderr, "direct tag mismatch\n");
        return 1;
    }

    memcpy(key_with_salt, key, sizeof(key));
    if (!check(srtp_sm4_gcm.alloc(&cipher, 28, 16) == srtp_err_status_ok,
               "alloc") ||
        !check(srtp_sm4_gcm.init(cipher->state, key_with_salt) ==
                   srtp_err_status_ok,
               "init") ||
        !check(srtp_sm4_gcm.set_iv(cipher->state, (uint8_t *)iv,
                                   srtp_direction_encrypt) ==
                   srtp_err_status_ok,
               "set iv") ||
        !check(srtp_sm4_gcm.set_aad(cipher->state, aad, sizeof(aad)) ==
                   srtp_err_status_ok,
               "set aad")) {
        return 1;
    }

    memcpy(packet, plaintext, sizeof(plaintext));
    if (!check(srtp_sm4_gcm.encrypt(cipher->state, packet, &packet_len) ==
                   srtp_err_status_ok,
               "encrypt") ||
        !check(packet_len == sizeof(plaintext), "encrypt length")) {
        srtp_sm4_gcm.dealloc(cipher);
        return 1;
    }
    if (memcmp(packet, ciphertext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "actual ciphertext: ");
        dump_hex(packet, sizeof(ciphertext));
        fprintf(stderr, "expected ciphertext: ");
        dump_hex(ciphertext, sizeof(ciphertext));
        srtp_sm4_gcm.dealloc(cipher);
        return 1;
    }
    if (!check(srtp_sm4_gcm.get_tag(cipher->state, actual_tag,
                                    &actual_tag_len) == srtp_err_status_ok,
               "get tag") ||
        !check(actual_tag_len == sizeof(tag) && !memcmp(actual_tag, tag, sizeof(tag)),
               "tag")) {
        srtp_sm4_gcm.dealloc(cipher);
        return 1;
    }

    memcpy(packet, ciphertext, sizeof(ciphertext));
    memcpy(packet + sizeof(ciphertext), tag, sizeof(tag));
    packet_len = sizeof(packet);
    if (!check(srtp_sm4_gcm.set_iv(cipher->state, (uint8_t *)iv,
                                   srtp_direction_decrypt) ==
                   srtp_err_status_ok,
               "set decrypt iv") ||
        !check(srtp_sm4_gcm.decrypt(cipher->state, packet, &packet_len) ==
                   srtp_err_status_ok,
               "decrypt") ||
        !check(packet_len == sizeof(plaintext) &&
                   !memcmp(packet, plaintext, sizeof(plaintext)),
               "plaintext")) {
        srtp_sm4_gcm.dealloc(cipher);
        return 1;
    }

    srtp_sm4_gcm.dealloc(cipher);
    puts("SM4-GCM adapter test passed");
    return 0;
}
