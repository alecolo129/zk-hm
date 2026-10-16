#include "universal_hash.h"
#include "toeplitz_internal.h"
#include <string.h>

static inline uint8_t row_product(const uint32_t *A, const uint32_t *r_words,
                                  size_t l_words, size_t row_start) {
  size_t shift = row_start % 32u;
  size_t base = row_start / 32u;
  uint32_t acc = 0;
  for (size_t j = 0; j < l_words; j++) {
    acc ^= toeplitz_load_window32(A, base + j, shift) & r_words[j];
  }
  return (uint8_t)__builtin_parity(acc);
}

static inline uint8_t bit_at(const uint8_t *bytes, size_t bit) {
  return (uint8_t)((bytes[bit / 8u] >> (bit % 8u)) & 1u);
}

void universal_hash_compute_b(uint8_t *b, const uint32_t *A,
                              const uint32_t *r_words, size_t l_words,
                              const uint8_t *message, size_t message_bit_len) {
  memset(b, 0, (message_bit_len + 7u) / 8u);
  for (size_t i = 0; i < message_bit_len; i++) {
    uint8_t bit = row_product(A, r_words, l_words, message_bit_len - 1u - i) ^
                  bit_at(message, i);
    b[i / 8u] |= (uint8_t)(bit << (i % 8u));
  }
}

int universal_hash_verify_message(const uint8_t *message,
                                  size_t message_bit_len, const uint8_t *b,
                                  const uint32_t *A, const uint32_t *r_words,
                                  size_t l_words) {
  for (size_t i = 0; i < message_bit_len; i++) {
    uint8_t recovered =
        row_product(A, r_words, l_words, message_bit_len - 1u - i) ^
        bit_at(b, i);
    if (recovered != bit_at(message, i)) {
      return -1;
    }
  }
  return 0;
}
