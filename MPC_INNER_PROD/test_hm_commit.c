#include "MPC_inner_prod.h"
#include "openssl/rand.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bit_commit {
  // commitment output
  uint8_t y[32];
  // universal hash function
  uint8_t A[L_BYTES];
  uint8_t b;
} bit_commit;

// For testing

void hm_bit_comit(const uint8_t m, const uint8_t r[L_BYTES],
                  bit_commit *commit) {
  MD(r, L_BYTES, commit->y);

  RAND_bytes(commit->A, L_BYTES);
  // b = Ar - m
  commit->b = 0;
  for (int i = 0; i < L_BYTES; i++) {
    commit->b ^= commit->A[i] & r[i];
  }
  commit->b =
      __builtin_parity((unsigned)commit->b); // accumulate b0..b7 into b0
  commit->b ^= m & 1;
}

void hm_bit_comit_words(const uint8_t m, const uint32_t r[L_WORDS],
                        uint8_t y[32], uint32_t A[L_WORDS], uint8_t *b) {
  MD((const unsigned char *)r, L_BYTES, y);

  RAND_bytes((unsigned char *)A,
             L_BYTES); // TODO: can it be generated with PRG?
  // b = Ar - m
  uint32_t acc = 0;
  for (int i = 0; i < L_WORDS; i++) {
    acc ^= A[i] & r[i];
  }
  *b = __builtin_parity(acc);
  *b ^= m & 1;
}

bool hm_bit_verify(const uint8_t m, const bit_commit *commit,
                   const uint8_t r[L_BYTES]) {
  // verify y = MD(r)
  uint8_t y_rec[32];
  MD(r, L_BYTES, y_rec);
  for (int i = 0; i < 32; i++) {
    if (y_rec[i] != commit->y[i])
      return false;
  }

  // verify Ar + b - m = 0
  uint8_t zero_bit = (commit->b & 1) ^ (m & 1);
  for (int i = 0; i < L_BYTES; i++) {
    zero_bit ^= commit->A[i] & r[i];
  }
  zero_bit = __builtin_parity((unsigned)zero_bit);

  return zero_bit == 0;
}

int main(void) {

  uint8_t m = 1;
  bit_commit comm;
  uint8_t r[L_BYTES];
  RAND_bytes(r, sizeof(r));
  // hm_bit_comit(m, r, &comm);
  hm_bit_comit_words(m, (const uint32_t *)r, comm.y, (uint32_t *)comm.A,
                     &comm.b);

  if (!hm_bit_verify(m, &comm, r)) {
    printf("Not verified!\n");
    return EXIT_FAILURE;
  }

  uint32_t A_words[L_WORDS];
  uint32_t r_words[L_WORDS];
  uint32_t rs[L_WORDS][3];
  uint32_t As[L_WORDS][3];
  for (int i = 0; i < L_WORDS; i++) {
    memcpy(&A_words[i], &comm.A[i * 4], sizeof(uint32_t));
    memcpy(&r_words[i], &r[i * 4], sizeof(uint32_t));
  };

  uint32_t shares[3];
  RAND_bytes((uint8_t *)shares, sizeof(shares));
  shares[0] = m ^ shares[1] ^ shares[2];

  for (int i = 0; i < L_WORDS; i++) {
    RAND_bytes((uint8_t *)rs[i], sizeof(rs[i]));
    rs[i][0] = r_words[i] ^ rs[i][1] ^ rs[i][2];

    RAND_bytes((uint8_t *)As[i], sizeof(As[i]));
    As[i][0] = A_words[i] ^ As[i][1] ^ As[i][2];
  }

  int countY = 0;
  View views[3];
  unsigned char *randomness[3];

  for (int i = 0; i < 3; i++) {
    randomness[i] = malloc(L_WORDS * sizeof(uint32_t));
    RAND_bytes(randomness[i], sizeof(randomness[i]));
  }

  mpc_inner_prod(shares, rs, As, randomness, views, &countY);

  uint32_t mpc_b =
      views[0].y2[L_WORDS] ^ views[1].y2[L_WORDS] ^ views[2].y2[L_WORDS];
  if (mpc_b != comm.b) {
    printf("Failure\n");
    return EXIT_FAILURE;
  }
  printf("Success!\n");
  return EXIT_SUCCESS;
}