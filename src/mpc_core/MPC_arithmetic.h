#ifndef MPC_ARITHMETIC_H
#define MPC_ARITHMETIC_H
#include "shared.h"
#include <stdint.h>

inline void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
  z[2] = x[2] ^ y[2];
}

inline void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

inline void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
}

inline void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
  z[2] = ~x[2];
}

inline void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
  z[2] = RIGHTROTATE(x[2], i);
}

inline void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
  z[2] = x[2] >> i;
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY);

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY);

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY);

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
            unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
            int *countY);

inline void mpc_ADDK_impl(uint32_t x[3], uint32_t y, uint32_t z[3],
                          unsigned char *randomness[3], int *randCount,
                          uint32_t *y_views[3], int *countY) {
  uint32_t ys[3] = {y, y, y};
  mpc_ADD(x, ys, z, randomness, randCount, y_views, countY);
}

inline void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
}

inline void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
}

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve,
                   View *ve1, unsigned char randomness[2][RAND_BYTES],
                   int *randCount, int *countY);

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve,
                   View *ve1, unsigned char randomness[2][RAND_BYTES],
                   int *randCount, int *countY);

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3],
                   View *ve, View *ve1, unsigned char randomness[2][RAND_BYTES],
                   int *randCount, int *countY);

inline int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2],
                         uint32_t z[2], View *ve, View *ve1,
                         unsigned char randomness[2][RAND_BYTES],
                         int *randCount, int *countY) {

  uint32_t t0[3];
  mpc_XOR2(f, g, t0);
  if (mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
    return 1;
  }
  mpc_XOR2(t0, g, z);

  return 0;
}

#endif