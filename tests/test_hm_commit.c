#include "MPC_inner_prod.h"
#include "openssl/rand.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct bit_commit {
  // commitment output
  uint8_t y[32];
  // universal hash function
  UniversalHash H;
} bit_commit;

// For testing
uint32_t inner_prod_prover(const UniversalHash H, const uint32_t r[L_WORDS],
                           const uint8_t m) {
  uint32_t y = 0;
  for (int i = 0; i < L_WORDS; i++) {
    y ^= H.A[i] & r[i];
  }
  return __builtin_parity(y);
}

uint32_t verify_universal_hash(const UniversalHash H, const uint32_t r[L_WORDS],
                               const uint8_t m) {
  uint32_t y = 0;
  for (int i = 0; i < L_WORDS; i++) {
    y ^= H.A[i] & r[i];
  }
  uint32_t b_rec = __builtin_parity(y);
  return (b_rec ^ m) == H.b;
}

void hm_bit_comit(const uint8_t m, const uint32_t r[L_WORDS], uint8_t y[32],
                  uint32_t A[L_WORDS], uint8_t *b) {
  MD((uint8_t *)r, L_BYTES, y);

  RAND_bytes((uint8_t *)A,
             L_BYTES); // TODO: can it be generated with PRG?
  // b = Ar - m
  uint32_t acc = 0;
  for (int i = 0; i < L_WORDS; i++) {
    acc ^= A[i] & r[i];
  }
  *b = __builtin_parity(acc);
  *b ^= m & 1;
}

bool hm_bit_verify(const uint32_t m, const bit_commit *commit,
                   const uint32_t r[L_WORDS]) {
  // verify y = MD(r)
  uint8_t y_rec[32];
  MD((uint8_t *)r, L_BYTES, y_rec);
  for (int i = 0; i < 32; i++) {
    if (y_rec[i] != commit->y[i])
      return false;
  }

  // verify Ar + b - m = 0
  UniversalHash H = commit->H;
  uint32_t zero_bit = (H.b & 1) ^ (m & 1);
  for (int i = 0; i < L_WORDS; i++) {
    zero_bit ^= H.A[i] & r[i];
  }
  zero_bit = __builtin_parity(zero_bit);

  return zero_bit == 0;
}

int main(void) {

  uint8_t msg = 1;
  RAND_bytes((uint8_t *)&msg, 1);
  msg&=1;
  uint32_t rWords[L_WORDS];
  RAND_bytes((uint8_t *)rWords, sizeof(rWords));

  {
    bit_commit comm;
    hm_bit_comit(msg, rWords, comm.y, comm.H.A, &comm.H.b);
    if (!hm_bit_verify(msg, &comm, rWords)) {
      printf("Not verified!\n");
      return EXIT_FAILURE;
    }
  }

  uint8_t keyA[16];
  RAND_bytes(keyA, sizeof(keyA));
  UniversalHash H;
  generate_H(H.A, &H.b, keyA, msg, rWords);
  if (!verify_universal_hash(H, rWords, msg)) {
    printf("Universal hash is malformed!\n");
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < 10000; i++) {
    uint32_t msgShares[3];
    RAND_bytes((uint8_t *)msgShares, sizeof(msgShares));
    msgShares[0] &= 1;
    msgShares[1] &= 1;
    msgShares[2] = msg ^ msgShares[0] ^ msgShares[1];

    uint32_t rShares[L_WORDS][3];
    RAND_bytes((uint8_t *)rShares, sizeof(rShares));
    for (int i = 0; i < L_WORDS; i++) {
      rShares[i][0] = rWords[i] ^ rShares[i][1] ^ rShares[i][2];
    }

    uint32_t ys[3] = {0};
    mpc_inner_prod_prover(&H, msgShares, rShares, ys);
    if (((ys[0] ^ ys[1] ^ ys[2]) ^ H.b) != 0) {
      printf("MPC prover produces unexpected result! - %d\n", i);
      exit(EXIT_FAILURE);
    }

    uint32_t e;
    RAND_bytes((uint8_t *)&e, 1);
    e %= 3;

    uint32_t openedShares[2] = {msgShares[e], msgShares[(e + 1) % 3]};
    uint32_t openedRs[L_WORDS][2];
    for (int k = 0; k < L_WORDS; k++) {
      openedRs[k][0] = rShares[k][e];
      openedRs[k][1] = rShares[k][(e + 1) % 3];
    }
    if (!mpc_inner_prod_verify(&H, openedShares, openedRs, ys, e)) {
      printf("MPC inner prod cannot verify! - %d\n", i);
      exit(EXIT_FAILURE);
    }
  }
  printf("Success!\n");
  return EXIT_SUCCESS;
}