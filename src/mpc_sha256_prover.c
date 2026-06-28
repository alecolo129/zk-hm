#include "mpc_arithmetic.h"
#include "mpc_sha256.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int mpc_sha256_prove_impl(const RVec shares[3],
                                 unsigned char *randomness[3], ViewsPtr views,
                                 int *countY);

void mpc_sha256_prove(const RVec shares[3], unsigned char *randomness[3],
                      View *views[3]) {

  // TODO: refactor and remove ViewsPtr
  ViewsPtr views_ptr;
  for (int j = 0; j < 3; j++) {
    views_ptr.x[j] = &views[j]->x;
    views_ptr.y[j] = views[j]->y;
  }

  int countY = 0;
  mpc_sha256_prove_impl(shares, randomness, views_ptr, &countY);
}

static int mpc_sha256_prove_impl(const RVec shares[3],
                                 unsigned char *randomness[3], ViewsPtr views,
                                 int *countY) {

  int randCount = 0;

  const size_t paddedLen = NUM_SHA256_BLOCKS * 64;
  unsigned char *padded[3];
  // Pre-processing (padding)
  for (int i = 0; i < 3; i++) {
    padded[i] = calloc(paddedLen, 1);
    memcpy(padded[i], rvec_const_bytes(&shares[i]),
           L_BYTES); // copy original share[i] in respective chunk[i]
    *views.x[i] = shares[i]; // set each party's SHA-256 input share x

    // append 1
    padded[i][L_BYTES] = 0x80;

    // Last 8 chars used for storing length of input without padding, in
    // big-endian.
    store_u64_be(&padded[i][paddedLen - 8], SHA256_INPUT_BITS);
  }

  uint32_t H[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]},
                      {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                      {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]},
                      {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};

  for (int blk = 0; blk < NUM_SHA256_BLOCKS; blk++) {

    uint32_t w[64][3];
    for (int i = 0; i < 3; i++) {
      const unsigned char *chunk = padded[i] + (blk * 64);
      for (int j = 0; j < 16; j++) {
        load_u32_be(&w[j][i], &chunk[j * 4]);
      }
    }

    uint32_t s0[3], s1[3];
    uint32_t t0[3], t1[3];
    for (int j = 16; j < 64; j++) {
      // s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^
      // (w[i][j-15] >> 3);
      mpc_RIGHTROTATE(w[j - 15], 7, t0);

      mpc_RIGHTROTATE(w[j - 15], 18, t1);
      mpc_XOR(t0, t1, t0);
      mpc_RIGHTSHIFT(w[j - 15], 3, t1);
      mpc_XOR(t0, t1, s0);

      // s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^
      // (w[i][j-2] >> 10);
      mpc_RIGHTROTATE(w[j - 2], 17, t0);
      mpc_RIGHTROTATE(w[j - 2], 19, t1);

      mpc_XOR(t0, t1, t0);
      mpc_RIGHTSHIFT(w[j - 2], 10, t1);
      mpc_XOR(t0, t1, s1);

      // w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

      mpc_ADD(w[j - 16], s0, t1, randomness, &randCount, views.y, countY);
      mpc_ADD(w[j - 7], t1, t1, randomness, &randCount, views.y, countY);
      mpc_ADD(t1, s1, w[j], randomness, &randCount, views.y, countY);
    }

    // Initialize working variables with current hash state
    uint32_t a[3], b[3], c[3], d[3], e[3], f[3], g[3], h[3];
    memcpy(a, H[0], sizeof(a));
    memcpy(b, H[1], sizeof(b));
    memcpy(c, H[2], sizeof(c));
    memcpy(d, H[3], sizeof(d));
    memcpy(e, H[4], sizeof(e));
    memcpy(f, H[5], sizeof(f));
    memcpy(g, H[6], sizeof(g));
    memcpy(h, H[7], sizeof(h));

    uint32_t temp1[3], temp2[3], maj[3];

    for (int i = 0; i < 64; i++) {
      // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
      mpc_RIGHTROTATE(e, 6, t0);
      mpc_RIGHTROTATE(e, 11, t1);
      mpc_XOR(t0, t1, t0);

      mpc_RIGHTROTATE(e, 25, t1);
      mpc_XOR(t0, t1, s1);

      // ch = (e & f) ^ ((~e) & g);
      // temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

      // t0 = h + s1

      mpc_ADD(h, s1, t0, randomness, &randCount, views.y, countY);

      mpc_CH(e, f, g, t1, randomness, &randCount, views.y, countY);

      // t1 = t0 + t1 (h+s1+ch)
      mpc_ADD(t0, t1, t1, randomness, &randCount, views.y, countY);

      mpc_ADDK_impl(t1, k[i], t1, randomness, &randCount, views.y, countY);

      mpc_ADD(t1, w[i], temp1, randomness, &randCount, views.y, countY);

      // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
      mpc_RIGHTROTATE(a, 2, t0);
      mpc_RIGHTROTATE(a, 13, t1);
      mpc_XOR(t0, t1, t0);
      mpc_RIGHTROTATE(a, 22, t1);
      mpc_XOR(t0, t1, s0);

      mpc_MAJ(a, b, c, maj, randomness, &randCount, views.y, countY);

      // temp2 = s0+maj;
      mpc_ADD(s0, maj, temp2, randomness, &randCount, views.y, countY);

      memcpy(h, g, sizeof(h));
      memcpy(g, f, sizeof(g));
      memcpy(f, e, sizeof(f));
      // e = d+temp1;
      mpc_ADD(d, temp1, e, randomness, &randCount, views.y, countY);
      memcpy(d, c, sizeof(d));
      memcpy(c, b, sizeof(c));
      memcpy(b, a, sizeof(b));
      // a = temp1+temp2;

      mpc_ADD(temp1, temp2, a, randomness, &randCount, views.y, countY);
    }

    mpc_ADD(H[0], a, H[0], randomness, &randCount, views.y, countY);
    mpc_ADD(H[1], b, H[1], randomness, &randCount, views.y, countY);
    mpc_ADD(H[2], c, H[2], randomness, &randCount, views.y, countY);
    mpc_ADD(H[3], d, H[3], randomness, &randCount, views.y, countY);
    mpc_ADD(H[4], e, H[4], randomness, &randCount, views.y, countY);
    mpc_ADD(H[5], f, H[5], randomness, &randCount, views.y, countY);
    mpc_ADD(H[6], g, H[6], randomness, &randCount, views.y, countY);
    mpc_ADD(H[7], h, H[7], randomness, &randCount, views.y, countY);
  }

  // copy each party's output into respective view 
  for (int i = 0; i < 8; i++) {
    views.y[0][*countY] = H[i][0];
    views.y[1][*countY] = H[i][1];
    views.y[2][*countY] = H[i][2];
    *countY += 1;
  }

  // Free padded shares
  for (int i = 0; i < 3; i++) {
    free(padded[i]);
  }

  return 0;
}
