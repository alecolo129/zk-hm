#include "mpc_arithmetic.h"
#include "string.h"

static inline uint32_t getRandom32(unsigned char randomness[RAND_BYTES],
                                   int randCount) {
  uint32_t ret;
  memcpy(&ret, &randomness[randCount], 4);
  return ret;
}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY) {
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

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY) {
  uint32_t t0[3];
  uint32_t t1[3];

  mpc_XOR(a, b, t0);
  mpc_XOR(a, c, t1);
  mpc_AND(t0, t1, z, randomness, randCount, y_views, countY);
  mpc_XOR(z, a, z);
}

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
            unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
            int *countY) {
  uint32_t t0[3];

  // e & (f^g) ^ g
  mpc_XOR(f, g, t0);
  mpc_AND(e, t0, t0, randomness, randCount, y_views, countY);
  mpc_XOR(t0, g, z);
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char *randomness[3], int *randCount, uint32_t *y_views[3],
             int *countY) {
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

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve,
                   View *ve1, unsigned char *randomness[2], int *randCount,
                   int *countY) {
  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;

  uint32_t t = 0;

  t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  if (ve->y[*countY] != t) {
    return -1;
  }
  z[0] = t;
  z[1] = ve1->y[*countY];

  (*countY)++;
  return 0;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve,
                   View *ve1, unsigned char *randomness[2], int *randCount,
                   int *countY) {

  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;

  uint8_t a[2], b[2];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ ve->y[*countY], i);
    a[1] = GETBIT(x[1] ^ ve1->y[*countY], i);

    b[0] = GETBIT(y[0] ^ ve->y[*countY], i);
    b[1] = GETBIT(y[1] ^ ve1->y[*countY], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    if (GETBIT(ve->y[*countY], i + 1) !=
        (t ^ (a[0] & b[0]) ^ GETBIT(ve->y[*countY], i) ^ GETBIT(r[0], i))) {
      return -1;
    }
  }

  z[0] = x[0] ^ y[0] ^ ve->y[*countY];
  z[1] = x[1] ^ y[1] ^ ve1->y[*countY];
  (*countY)++;
  return 0;
}

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[2],
                   View *ve, View *ve1, unsigned char *randomness[2],
                   int *randCount, int *countY) {
  uint32_t t0[2];
  uint32_t t1[2];

  mpc_XOR2(a, b, t0);
  mpc_XOR2(a, c, t1);
  if (mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) != 0) {
    return -1;
  }
  mpc_XOR2(z, a, z);
  return 0;
}
