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
                              const uint32_t m[MSG_WORDS][3], const RVec r[3],
                              uint32_t y[MSG_WORDS][3]);

int mpc_universal_hash_verify(const UniversalHash *h,
                              const uint32_t m[MSG_WORDS][2], const RVec r[2],
                              const uint32_t y[MSG_WORDS][3], const uint32_t e);


void mpc_hm_expand_matrix(uint32_t *A, size_t a_words, const uint8_t keyA[16]);

void mpc_hm_hash_init(uint32_t A[A_WORDS], uint8_t b[MSG_BYTES],
                      const uint8_t keyH[16], const uint8_t m[MSG_BYTES],
                      const RVec *r);

#ifdef __cplusplus
}
#endif
