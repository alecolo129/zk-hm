#include "MPC_inner_prod.h"
#include "MPC_SHA256.h"

void mpc_parity(uint32_t x[3], uint32_t z[3]) {
  z[0] = __builtin_parity(x[0]);
  z[1] = __builtin_parity(x[1]);
  z[2] = __builtin_parity(x[2]);
}

void mpc_inner_prod(uint32_t shares[3], uint32_t r[L_WORDS][3],
                    uint32_t A[L_WORDS][3], unsigned char *randomness[3],
                    View views[3], int *countY) {

  uint32_t acc[3] = {0};
  uint32_t t1[3];
  int randCount = 0;

  uint32_t *y_views[3] = {views[0].y2, views[1].y2, views[2].y2};
  for (int i = 0; i < L_WORDS; i++) {
    mpc_AND_impl(A[i], r[i], t1, randomness, &randCount, y_views, countY);
    mpc_XOR(acc, t1, acc);
  }
  mpc_parity(acc, acc);
  mpc_XOR(acc, shares, acc);

  // save shares of b
  y_views[0][*countY] = acc[0];
  y_views[1][*countY] = acc[1];
  y_views[2][*countY] = acc[2];
}
