#include "mpc_halevi_micali.h"
#include "mpc_core_funcs.h"
#include "mpc_sha256.h"
#include "mpc_universal_hash.h"
#include "random_oracle.h"
#include "shared.h"
#include <stdio.h>

inline size_t min(size_t a, size_t b) { return a <= b ? a : b; }

// prover
void mpc_hm_prove(View *localViews[3], ZkBooCommit *as, uint8_t *randomness[3],
                  uint8_t rs[3][4], const UniversalHash *h,
                  uint8_t rShares[3][L_BYTES],
                  const uint32_t msgShares[MSG_WORDS][3]) {

  // prove y = SHA256(r)
  mpc_sha256_prove(rShares, randomness, localViews);

  // copy last part of the view.y (i.e., SHA256 output) into a.yp
  output(localViews[0], as->yp[0]);
  output(localViews[1], as->yp[1]);
  output(localViews[2], as->yp[2]);

  // prove H(r) = m
  uint32_t rWords[L_WORDS][3] = {0};
  for (int i = 0; i < L_WORDS; i++) {
    memcpy(&rWords[i][0], &rShares[0][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][1], &rShares[1][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][2], &rShares[2][i * 4], sizeof(uint32_t));
  }
  // copy msg share into respective local view
  for (int i = 0; i < MSG_WORDS; i++) {
    memcpy(&localViews[0]->msg[i * 4], &msgShares[i][0], sizeof(uint32_t));
    memcpy(&localViews[1]->msg[i * 4], &msgShares[i][1], sizeof(uint32_t));
    memcpy(&localViews[2]->msg[i * 4], &msgShares[i][2], sizeof(uint32_t));
  }
  mpc_universal_hash_prove(h, msgShares, rWords, as->y2p);
}

// verifier

static int verify_commit(ZkBooCommit *a, int e, ZkBooOpen *z) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  H(z->ke, z->ve, z->re, hash);
  if (memcmp(a->h[e], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return -1;
  }

  H(z->ke1, z->ve1, z->re1, hash);
  if (memcmp(a->h[(e + 1) % 3], hash, 32) != 0) {
    LOG_ERRF("Hash verification failed");
    return -1;
  }

  return 0;
}

int mpc_hm_verify(UniversalHash *H, ZkBooCommit *a, ZkBooOpen *z, int e) {

  if (verify_commit(a, e, z) != 0) {
    return -1;
  }
  if (mpc_sha256_verify(a, e, z) != 0) {
    return -1;
  }

  uint32_t m[MSG_WORDS][2];
  for (int i = 0; i < MSG_WORDS; i++) {
    load_u32_le(&m[i][0], &z->ve->msg[i * 4]);
    load_u32_le(&m[i][1], &z->ve1->msg[i * 4]);
  };
  uint32_t r[L_WORDS][2];
  for (int j = 0; j < L_WORDS; j++) {
    memcpy(&r[j][0], &z->ve->x[j * 4], sizeof(uint32_t));
    memcpy(&r[j][1], &z->ve1->x[j * 4], sizeof(uint32_t));
  }

  if (mpc_universal_hash_verify(H, m, r, a->y2p, e) != 0) {
    return -1;
  }

  return 0;
}