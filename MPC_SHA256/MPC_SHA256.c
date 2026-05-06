/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
 */

#include "MPC_SHA256.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mpc_AND_impl(uint32_t x[3], uint32_t y[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY);

void mpc_ADD_impl(uint32_t x[3], uint32_t y[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY);

void mpc_ADDK_impl(uint32_t x[3], uint32_t y, uint32_t z[3],
                   unsigned char *randomness[3], int *randCount,
                   uint32_t *y_views[3], int *countY);

void mpc_MAJ_impl(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY);

void mpc_CH_impl(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
                 unsigned char *randomness[3], int *randCount,
                 uint32_t *y_views[3], int *countY);

int mpc_sha256(unsigned char *results[3], unsigned char *inputs[3], int numBits,
               unsigned char *randomness[3], ViewsPtr views, int *countY);

uint32_t rand32() {
  uint32_t x;
  x = rand() & 0xff;
  x |= (rand() & 0xff) << 8;
  x |= (rand() & 0xff) << 16;
  x |= (rand() & 0xff) << 24;

  return x;
}

void printbits(uint32_t n) {
  if (n) {
    printbits(n >> 1);
    printf("%d", n & 1);
  }
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, View views[3],
             int *countY) {
  uint32_t *y_views[3] = {views[0].y, views[1].y, views[2].y};
  mpc_AND_impl(x, y, z, randomness, randCount, y_views, countY);
}

void mpc_AND_impl(uint32_t x[3], uint32_t y[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY) {
  uint32_t r[3] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount),
                   getRandom32(randomness[2], *randCount)};
  *randCount += 4;
  uint32_t t[3] = {0};

  t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
  t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
  z[0] = t[0];
  z[1] = t[1];
  z[2] = t[2];
  y_views[0][*countY] = z[0];
  y_views[1][*countY] = z[1];
  y_views[2][*countY] = z[2];
  (*countY)++;
}

void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
  z[2] = ~x[2];
}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, View views[3],
             int *countY) {
  uint32_t *y_views[3] = {views[0].y, views[1].y, views[2].y};
  mpc_ADD_impl(x, y, z, randomness, randCount, y_views, countY);
}

void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3],
              unsigned char *randomness[3], int *randCount, View views[3],
              int *countY) {
  uint32_t *y_views[3] = {views[0].y, views[1].y, views[2].y};
  mpc_ADDK_impl(x, y, z, randomness, randCount, y_views, countY);
}

void mpc_ADDK_impl(uint32_t x[3], uint32_t y, uint32_t z[3],
                   unsigned char *randomness[3], int *randCount,
                   uint32_t *y_views[3], int *countY) {
  uint32_t ys[3] = {y, y, y};
  mpc_ADD_impl(x, ys, z, randomness, randCount, y_views, countY);
}

void mpc_ADD_impl(uint32_t x[3], uint32_t y[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY) {
  uint32_t c[3] = {0};
  uint32_t r[3] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount),
                   getRandom32(randomness[2], *randCount)};
  *randCount += 4;

  uint8_t a[3], b[3];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ c[0], i);
    a[1] = GETBIT(x[1] ^ c[1], i);
    a[2] = GETBIT(x[2] ^ c[2], i);

    b[0] = GETBIT(y[0] ^ c[0], i);
    b[1] = GETBIT(y[1] ^ c[1], i);
    b[2] = GETBIT(y[2] ^ c[2], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

    t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
    SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

    t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
    SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
  }

  z[0] = x[0] ^ y[0] ^ c[0];
  z[1] = x[1] ^ y[1] ^ c[1];
  z[2] = x[2] ^ y[2] ^ c[2];

  y_views[0][*countY] = c[0];
  y_views[1][*countY] = c[1];
  y_views[2][*countY] = c[2];
  *countY += 1;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
  z[2] = RIGHTROTATE(x[2], i);
}

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
  z[2] = x[2] >> i;
}

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, View views[3],
             int *countY) {
  uint32_t *y_views[3] = {views[0].y, views[1].y, views[2].y};
  mpc_MAJ_impl(a, b, c, z, randomness, randCount, y_views, countY);
}

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
            unsigned char *randomness[3], int *randCount, View views[3],
            int *countY) {
  uint32_t *y_views[3] = {views[0].y, views[1].y, views[2].y};
  mpc_CH_impl(e, f, g, z, randomness, randCount, y_views, countY);
}

void mpc_MAJ_impl(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
                  unsigned char *randomness[3], int *randCount,
                  uint32_t *y_views[3], int *countY) {
  uint32_t t0[3];
  uint32_t t1[3];

  mpc_XOR(a, b, t0);
  mpc_XOR(a, c, t1);
  mpc_AND_impl(t0, t1, z, randomness, randCount, y_views, countY);
  mpc_XOR(z, a, z);
}

void mpc_CH_impl(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
                 unsigned char *randomness[3], int *randCount,
                 uint32_t *y_views[3], int *countY) {
  uint32_t t0[3];

  // e & (f^g) ^ g
  mpc_XOR(f, g, t0);
  mpc_AND_impl(e, t0, t0, randomness, randCount, y_views, countY);
  mpc_XOR(t0, g, z);
}

int mpc_sha256(unsigned char *results[3], unsigned char *inputs[3], int numBits,
               unsigned char *randomness[3], ViewsPtr views, int *countY) {

  int randCount = 0;
  int numBytes = numBits >> 3;

  const size_t paddedLen = NUM_SHA256_BLOCKS * 64;
  unsigned char *padded[3];
  // Pre-processing (padding)
  for (int i = 0; i < 3; i++) {
    padded[i] = calloc(paddedLen, 1);
    memcpy(padded[i], inputs[i],
           numBytes); // copy original share[i] in respective chunk[i]
    memcpy(views.x[i], inputs[i],
           numBytes); // set each party's SHA-256 input as it's secret share x

    // append 1
    padded[i][numBytes] = 0x80;

    // Last 8 chars used for storing length of input without padding, in
    // big-endian.
    store_u64_be(&padded[i][paddedLen - 8], numBits);
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
        load_u32_be(&w[j][i], &chunk[j*4]);
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

      mpc_ADD_impl(w[j - 16], s0, t1, randomness, &randCount, views.y, countY);
      mpc_ADD_impl(w[j - 7], t1, t1, randomness, &randCount, views.y, countY);
      mpc_ADD_impl(t1, s1, w[j], randomness, &randCount, views.y, countY);
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

      mpc_ADD_impl(h, s1, t0, randomness, &randCount, views.y, countY);

      mpc_CH_impl(e, f, g, t1, randomness, &randCount, views.y, countY);

      // t1 = t0 + t1 (h+s1+ch)
      mpc_ADD_impl(t0, t1, t1, randomness, &randCount, views.y, countY);

      mpc_ADDK_impl(t1, k[i], t1, randomness, &randCount, views.y, countY);

      mpc_ADD_impl(t1, w[i], temp1, randomness, &randCount, views.y, countY);

      // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
      mpc_RIGHTROTATE(a, 2, t0);
      mpc_RIGHTROTATE(a, 13, t1);
      mpc_XOR(t0, t1, t0);
      mpc_RIGHTROTATE(a, 22, t1);
      mpc_XOR(t0, t1, s0);

      mpc_MAJ_impl(a, b, c, maj, randomness, &randCount, views.y, countY);

      // temp2 = s0+maj;
      mpc_ADD_impl(s0, maj, temp2, randomness, &randCount, views.y, countY);

      memcpy(h, g, sizeof(h));
      memcpy(g, f, sizeof(g));
      memcpy(f, e, sizeof(f));
      // e = d+temp1;
      mpc_ADD_impl(d, temp1, e, randomness, &randCount, views.y, countY);
      memcpy(d, c, sizeof(d));
      memcpy(c, b, sizeof(c));
      memcpy(b, a, sizeof(b));
      // a = temp1+temp2;

      mpc_ADD_impl(temp1, temp2, a, randomness, &randCount, views.y, countY);
    }

    mpc_ADD_impl(H[0], a, H[0], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[1], b, H[1], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[2], c, H[2], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[3], d, H[3], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[4], e, H[4], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[5], f, H[5], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[6], g, H[6], randomness, &randCount, views.y, countY);
    mpc_ADD_impl(H[7], h, H[7], randomness, &randCount, views.y, countY);
  }

  // Free padded shares
  for (int i = 0; i < 3; i++) {
    free(padded[i]);
  }

  uint32_t t0[3];

  // produce the final hash value (big endian)
  // append each hHa[i] converting int into char
  for (int i = 0; i < 8; i++) {
    mpc_RIGHTSHIFT(H[i], 24, t0);
    results[0][i * 4] = t0[0];
    results[1][i * 4] = t0[1];
    results[2][i * 4] = t0[2];
    mpc_RIGHTSHIFT(H[i], 16, t0);
    results[0][i * 4 + 1] = t0[0];
    results[1][i * 4 + 1] = t0[1];
    results[2][i * 4 + 1] = t0[2];
    mpc_RIGHTSHIFT(H[i], 8, t0);
    results[0][i * 4 + 2] = t0[0];
    results[1][i * 4 + 2] = t0[1];
    results[2][i * 4 + 2] = t0[2];

    results[0][i * 4 + 3] = H[i][0];
    results[1][i * 4 + 3] = H[i][1];
    results[2][i * 4 + 3] = H[i][2];
  }

  return 0;
}

int writeToFile(char filename[], void *data, int size, int numItems) {
  FILE *file;

  file = fopen(filename, "wb");
  if (!file) {
    printf("Unable to open file!");
    return 1;
  }
  fwrite(data, size, numItems, file);
  fclose(file);
  return 0;
}

int secretShare(unsigned char *input, int numBytes,
                unsigned char output[3][numBytes]) {
  if (RAND_bytes(output[0], numBytes) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
  }
  if (RAND_bytes(output[1], numBytes) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
  }
  for (int j = 0; j < numBytes; j++) {
    output[2][j] = input[j] ^ output[0][j] ^ output[1][j];
  }
  return 0;
}

void generate_randomness(unsigned int numRounds,
                         unsigned char keys[numRounds][3][16],
                         unsigned char *randomness[numRounds][3]) {
#pragma omp parallel for
  for (int k = 0; k < numRounds; k++) {
    for (int j = 0; j < 3; j++) {
      // Note: In the MPC protocol we need 32 bit of randomness for each ADD/AND
      // operation in SHA256 (operates on 32bit words). We have 64 AND gates and
      // 664 ADD gates, so we need 728 * 32 / 8 = 2912 bytes of randomness.
      randomness[k][j] = malloc(NUM_SHA256_BLOCKS * 2912 * sizeof(unsigned char));
      getAllRandomness(keys[k][j], randomness[k][j]);
    }
  }
}

void commit_impl(int numBytes, unsigned char shares[3][numBytes],
                 unsigned char *randomness[3], ViewsPtr views) {

  unsigned char *inputs[3];
  inputs[0] = shares[0];
  inputs[1] = shares[1];
  inputs[2] = shares[2];
  unsigned char *hashes[3];
  hashes[0] = malloc(32);
  hashes[1] = malloc(32);
  hashes[2] = malloc(32);

  int countY = 0;
  mpc_sha256(hashes, inputs, numBytes * 8, randomness, views, &countY);

  // Explicitly add y to view
  for (int i = 0; i < 8; i++) {
    views.y[0][countY] = (hashes[0][i * 4] << 24) |
                         (hashes[0][i * 4 + 1] << 16) |
                         (hashes[0][i * 4 + 2] << 8) | hashes[0][i * 4 + 3];

    views.y[1][countY] = (hashes[1][i * 4] << 24) |
                         (hashes[1][i * 4 + 1] << 16) |
                         (hashes[1][i * 4 + 2] << 8) | hashes[1][i * 4 + 3];
    views.y[2][countY] = (hashes[2][i * 4] << 24) |
                         (hashes[2][i * 4 + 1] << 16) |
                         (hashes[2][i * 4 + 2] << 8) | hashes[2][i * 4 + 3];
    countY += 1;
  }
  free(hashes[0]);
  free(hashes[1]);
  free(hashes[2]);
}

void commit(int numBytes, unsigned char shares[3][numBytes],
            unsigned char *randomness[3], unsigned char rs[3][4],
            View views[3]) {

  ViewsPtr views_ptr;
  for (int j = 0; j < 3; j++) {
    views_ptr.x[j] = views[j].x;
    views_ptr.y[j] = views[j].y;
  }

  commit_impl(numBytes, shares, randomness, views_ptr);
}

void commit2(int numBytes, unsigned char shares[3][numBytes],
             unsigned char *randomness[3], View2 views[3]) {

  ViewsPtr views_ptr;
  for (int j = 0; j < 3; j++) {
    views_ptr.x[j] = views[j].x;
    views_ptr.y[j] = views[j].y[0];
  }

  commit_impl(numBytes, shares, randomness, views_ptr);
  for (int j = 0; j < 3; j++) {
    views_ptr.y[j] = views[j].y[1];
  }
  commit_impl(numBytes, shares, randomness, views_ptr);
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4],
        View views[3]) {
  z z;
  memcpy(z.ke, keys[e], 16);
  memcpy(z.ke1, keys[(e + 1) % 3], 16);
  z.ve = views[e];
  z.ve1 = views[(e + 1) % 3];
  memcpy(z.re, rs[e], 4);
  memcpy(z.re1, rs[(e + 1) % 3], 4);

  return z;
}

z2 prove2(int e, unsigned char keys[3][16], unsigned char rs[3][4],
          View2 views[3]) {
  z2 z;
  memcpy(z.ke, keys[e], 16);
  memcpy(z.ke1, keys[(e + 1) % 3], 16);
  z.ve = views[e];
  z.ve1 = views[(e + 1) % 3];
  memcpy(z.re, rs[e], 4);
  memcpy(z.re1, rs[(e + 1) % 3], 4);

  return z;
}
