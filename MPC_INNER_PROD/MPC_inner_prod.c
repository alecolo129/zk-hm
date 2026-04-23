#include "MPC_inner_prod.h"
#include "shared.h"
#include "stdbool.h"
#include <stdint.h>
#include <stdio.h>

void mpc_parity(uint32_t x[3], uint32_t z[3]) {
  z[0] = __builtin_parity(x[0]);
  z[1] = __builtin_parity(x[1]);
  z[2] = __builtin_parity(x[2]);
}

void mpc_parity2(uint32_t x[2], uint32_t z[2]) {
  z[0] = __builtin_parity(x[0]);
  z[1] = __builtin_parity(x[1]);
}

void mpc_ANDK(const uint32_t x[3], const uint32_t y, uint32_t z[3]) {
  z[0] = x[0] & y;
  z[1] = x[1] & y;
  z[2] = x[2] & y;
}

void mpc_ANDK2(const uint32_t x[2], const uint32_t y, uint32_t z[2]) {
  z[0] = x[0] & y;
  z[1] = x[1] & y;
}

void mpc_XORK(const uint32_t x[3], const uint32_t y, uint32_t z[3]) {
  z[0] = x[0] ^ y;
}

void mpc_XORK2(const uint32_t x[2], const uint32_t y, uint32_t z[2]) {
  z[0] = x[0] ^ y;
}

inline void mpc_XOR2_const(uint32_t x[2], const uint32_t y[2], uint32_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

void generate_H(const uint8_t m, const uint32_t r[L_WORDS], uint32_t A[L_WORDS],
                uint8_t *b) {

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

void mpc_inner_prod_prover(const UniversalHash h, const uint32_t m[3],
                           const uint32_t r[L_WORDS][3], uint32_t y[3]) {
  uint32_t t1[3] = {0};
  for (int i = 0; i < L_WORDS; i++) {
    mpc_ANDK(r[i], h.A[i], t1);
    mpc_XOR(y, t1, y);
  }
  mpc_parity(y, y);
}

bool mpc_inner_prod_verify(const UniversalHash h, const uint32_t m[2],
                           const uint32_t r[L_WORDS][2], const uint32_t y[3],
                           const uint32_t e) {
  uint32_t y_rec[2] = {0};
  uint32_t t1[2];
  for (int i = 0; i < L_WORDS; i++) {
    mpc_ANDK2(r[i], h.A[i], t1);
    mpc_XOR2(y_rec, t1, y_rec);
  }
  mpc_parity2(y_rec, y_rec);

  if (y[e] != y_rec[0] || y[(e + 1) % 3] != y_rec[1]) {
    printf("Failed at line %d\n", __LINE__);
    return false;
  }

  mpc_XORK2(y_rec, h.b, y_rec);
  mpc_XOR2_const(y_rec, m, y_rec);

  return y_rec[0] ^ y_rec[1] ^ y[(e + 2) % 3] == 0;
}
