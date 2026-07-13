#pragma once
#include "shared.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mpc_inner_prod_prove(const UniversalHash *h, const uint32_t m[3],
                          const RVec r[3], uint32_t y[3]);

int mpc_inner_prod_verify(const UniversalHash *h, const uint32_t m[2],
                          const RVec r[2], const uint32_t y[3],
                          const uint32_t e);

void mpc_universal_hash_prove(const UniversalHash *h,
                              const uint32_t m[MSG_WORDS][3],
                              const RVec r[3],
                              uint32_t y[MSG_WORDS][3]);

int mpc_universal_hash_verify(const UniversalHash *h,
                              const uint32_t m[MSG_WORDS][2],
                              const RVec r[2],
                              const uint32_t y[MSG_WORDS][3],
                              const uint32_t e);

void expand_A(uint32_t *A, size_t a_words, const uint8_t keyA[16]);

void generate_H(uint32_t A[A_WORDS], uint8_t b[MSG_BYTES],
                const uint8_t keyH[16], const uint8_t m[MSG_BYTES],
                const RVec *r);

void universal_hash_load_words(uint32_t *dst_words, const uint8_t *src,
                               size_t src_len, size_t word_len);

void universal_hash_compute_b(uint8_t *b, const uint32_t *A,
                              const uint32_t *r_words, size_t l_words,
                              const uint8_t *message,
                              size_t message_bit_len);

int universal_hash_verify_message(const uint8_t *message,
                                  size_t message_bit_len, const uint8_t *b,
                                  const uint32_t *A,
                                  const uint32_t *r_words, size_t l_words);

#ifdef __cplusplus
}
#endif
