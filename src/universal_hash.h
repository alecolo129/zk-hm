#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plain HM hashing with LSB-first Toeplitz diagonals: row i starts at
 * message_bit_len - 1 - i. A must include a readable lookahead word for each
 * window; r_words holds exactly the opening bits with zero word padding. */
void universal_hash_compute_b(uint8_t *b, const uint32_t *A,
                              const uint32_t *r_words, size_t l_words,
                              const uint8_t *message, size_t message_bit_len);

int universal_hash_verify_message(const uint8_t *message,
                                  size_t message_bit_len, const uint8_t *b,
                                  const uint32_t *A, const uint32_t *r_words,
                                  size_t l_words);

#ifdef __cplusplus
}
#endif
