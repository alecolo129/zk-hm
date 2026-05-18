#include "MPC_SHA256_VERIFIER.h"
#include "MPC_arithmetic.h"
#include "shared.h"
#include "stdbool.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool verify_hash(a *a, int e, z *z) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  H(z->ke, z->ve, z->re, hash);
  if (memcmp(a->h[e], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return false;
  }

  H(z->ke1, z->ve1, z->re1, hash);
  if (memcmp(a->h[(e + 1) % 3], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return false;
  }

  return true;
}

int verify_hash2(a2 a, int e, z2 z) {

  unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

  H2(z.ke, z.ve, z.re, hash);
  if (memcmp(a.h[e], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return 1;
  }

  H2(z.ke1, z.ve1, z.re1, hash);
  if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return 1;
  }

  free(hash);
  return 0;
}

int verify(a *a, int e, z *z) {

  uint32_t *result = malloc(32);
  output(z->ve, result);
  if (memcmp(a->yp[e], result, 32) != 0) {
    LOG_ERRF("Committed outputs inconsistent with opening");
    return 1;
  }

  output(z->ve1, result);
  if (memcmp(a->yp[(e + 1) % 3], result, 32) != 0) {
    LOG_ERRF("Committed outputs inconsistent with opening");
    return 1;
  }

  free(result);

  unsigned char *randomness[2];
  randomness[0] = malloc(2*RAND_BYTES);
  randomness[1] = randomness[0] + RAND_BYTES;
  getAllRandomness(z->ke, randomness[0]);
  getAllRandomness(z->ke1, randomness[1]);

  int randCount = 0;
  int countY = 0;

  const size_t paddedLen = NUM_SHA256_BLOCKS * 64;
  uint8_t *padded[2] = {calloc(paddedLen, 1), calloc(paddedLen, 1)};
  mempcpy(padded[0], z->ve->x, L_BYTES);
  mempcpy(padded[1], z->ve1->x, L_BYTES);

  // padding
  for (int i = 0; i < 2; i++) {
    padded[i][L_BYTES] = 0x80;
    store_u64_be(&padded[i][paddedLen - 8], L_BITS);
  }

  uint32_t H[8][2] = {{hA[0], hA[0]}, {hA[1], hA[1]}, {hA[2], hA[2]},
                      {hA[3], hA[3]}, {hA[4], hA[4]}, {hA[5], hA[5]},
                      {hA[6], hA[6]}, {hA[7], hA[7]}};

  for (int blk = 0; blk < NUM_SHA256_BLOCKS; blk++) {
    uint32_t w[64][2];

    const unsigned char *chunk[2] = {padded[0] + (blk * 64),
                                     padded[1] + (blk * 64)};
    for (int j = 0; j < 16; j++) {
      load_u32_be(&w[j][0], &chunk[0][j * 4]);
      load_u32_be(&w[j][1], &chunk[1][j * 4]);
    }

    uint32_t s0[2], s1[2];
    uint32_t t0[2], t1[2];
    for (int j = 16; j < 64; j++) {
      // s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^
      // (w[i][j-15] >> 3);
      mpc_RIGHTROTATE2(w[j - 15], 7, t0);
      mpc_RIGHTROTATE2(w[j - 15], 18, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
      mpc_XOR2(t0, t1, s0);

      // s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^
      // (w[i][j-2] >> 10);
      mpc_RIGHTROTATE2(w[j - 2], 17, t0);
      mpc_RIGHTROTATE2(w[j - 2], 19, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
      mpc_XOR2(t0, t1, s1);

      // w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
      if (mpc_ADD_verify(w[j - 16], s0, t1, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", j);
        return 1;
      }

      if (mpc_ADD_verify(w[j - 7], t1, t1, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", j);
        return 1;
      }
      if (mpc_ADD_verify(t1, s1, w[j], z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", j);
        return 1;
      }
    }
    uint32_t va[2], vb[2], vc[2], vd[2], ve[2], vf[2], vg[2], vh[2];
    memcpy(va, H[0], sizeof(va));
    memcpy(vb, H[1], sizeof(vb));
    memcpy(vc, H[2], sizeof(vc));
    memcpy(vd, H[3], sizeof(vd));
    memcpy(ve, H[4], sizeof(ve));
    memcpy(vf, H[5], sizeof(vf));
    memcpy(vg, H[6], sizeof(vg));
    memcpy(vh, H[7], sizeof(vh));

    uint32_t temp1[3], temp2[3], maj[3];
    for (int i = 0; i < 64; i++) {
      // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
      mpc_RIGHTROTATE2(ve, 6, t0);
      mpc_RIGHTROTATE2(ve, 11, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTROTATE2(ve, 25, t1);
      mpc_XOR2(t0, t1, s1);

      // ch = (e & f) ^ ((~e) & g);
      // temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

      // t0 = h + s1

      if (mpc_ADD_verify(vh, s1, t0, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {

        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      if (mpc_CH_verify(ve, vf, vg, t1, z->ve, z->ve1, randomness, &randCount,
                        &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      // t1 = t0 + t1 (h+s1+ch)
      if (mpc_ADD_verify(t0, t1, t1, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      t0[0] = k[i];
      t0[1] = k[i];
      if (mpc_ADD_verify(t1, t0, t1, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      if (mpc_ADD_verify(t1, w[i], temp1, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
      mpc_RIGHTROTATE2(va, 2, t0);
      mpc_RIGHTROTATE2(va, 13, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTROTATE2(va, 22, t1);
      mpc_XOR2(t0, t1, s0);

      // maj = (a & (b ^ c)) ^ (b & c);
      //(a & b) ^ (a & c) ^ (b & c)

      if (mpc_MAJ_verify(va, vb, vc, maj, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      // temp2 = s0+maj;
      if (mpc_ADD_verify(s0, maj, temp2, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      memcpy(vh, vg, sizeof(vh));
      memcpy(vg, vf, sizeof(vg));
      memcpy(vf, ve, sizeof(vf));
      // e = d+temp1;
      if (mpc_ADD_verify(vd, temp1, ve, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }

      memcpy(vd, vc, sizeof(vd));
      memcpy(vc, vb, sizeof(vc));
      memcpy(vb, va, sizeof(vb));
      // a = temp1+temp2;

      if (mpc_ADD_verify(temp1, temp2, va, z->ve, z->ve1, randomness, &randCount,
                         &countY) == 1) {
        LOG_ERRF("MPC verification failed, iteration %d", i);
        return 1;
      }
    }

    if (mpc_ADD_verify(H[0], va, H[0], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[1], vb, H[1], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[2], vc, H[2], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[3], vd, H[3], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[4], ve, H[4], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[5], vf, H[5], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[6], vg, H[6], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
    if (mpc_ADD_verify(H[7], vh, H[7], z->ve, z->ve1, randomness, &randCount,
                       &countY) == 1) {
      LOG_ERRF("MPC verification failed");
      return 1;
    }
  }

  for (int i = 0; i < 8; i++) {
    if ((H[i][0] != a->yp[e][i]) || (H[i][1] != a->yp[(e + 1) % 3][i])) {
      LOG_ERRF("Reconstructed output shares don't match commitment");
      return 1;
    }
  }
  
  free(randomness[0]);

  return 0;
}