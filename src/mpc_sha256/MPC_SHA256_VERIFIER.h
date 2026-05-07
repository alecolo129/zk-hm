#ifndef MPC_SHA256_VERIFIER_H_
#define MPC_SHA256_VERIFIER_H_
#include "shared.h"
#include "stdbool.h"

inline void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
}

inline void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
}

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve,
                   View ve1, unsigned char randomness[2][RAND_BYTES], int *randCount,
                   int *countY);

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve,
                   View ve1, unsigned char randomness[2][RAND_BYTES], int *randCount,
                   int *countY);

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3],
                   View ve, View ve1, unsigned char randomness[2][RAND_BYTES],
                   int *randCount, int *countY);

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2],
                  View ve, View ve1, unsigned char randomness[2][RAND_BYTES],
                  int *randCount, int *countY);

bool verify_hash(a a, int e, z z);
int verify_hash2(a2 a, int e, z2 z);

int verify(a a, int e, z z);

#endif
