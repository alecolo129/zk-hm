#include "mpc_halevi_micali.h"
#include "mpc_core_funcs.h"
#include "mpc_sha256.h"
#include "mpc_universal_hash.h"
#include "random_oracle.h"
#include "shared.h"
#include <stdio.h>
#include <string.h>

// prover
void mpc_hm_prove(View *localViews[3], ZkBooCommit *as, uint8_t *randomness[3],
                  uint8_t rs[3][4], const UniversalHash *h,
                  RVec rShares[3],
                  const uint32_t msgShares[MSG_WORDS][3]) {

  // prove y = SHA256(r)
  mpc_sha256_prove(rShares, randomness, localViews);

  // copy last part of the view.y (i.e., SHA256 output) into a.yp
  output(localViews[0], as->yp[0]);
  output(localViews[1], as->yp[1]);
  output(localViews[2], as->yp[2]);

  // copy msg share into respective local view
  for (int i = 0; i < MSG_WORDS; i++) {
    memcpy(&localViews[0]->msg[i * 4], &msgShares[i][0], sizeof(uint32_t));
    memcpy(&localViews[1]->msg[i * 4], &msgShares[i][1], sizeof(uint32_t));
    memcpy(&localViews[2]->msg[i * 4], &msgShares[i][2], sizeof(uint32_t));
  }
  mpc_inner_prod_prove(h, msgShares[0], rShares, as->y2p[0]);
}

// verifier

static int verify_commit(const ZkBooCommit *a, const ZkBooOpen *z, const uint8_t y[SHA256_DIGEST_LENGTH], int e) {

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

  uint8_t y_rec[SHA256_DIGEST_LENGTH];
  reconstruct(a->yp[0], a->yp[1], a->yp[2], y_rec);
  if(memcmp(y, y_rec, SHA256_DIGEST_LENGTH) != 0) {
    LOG_ERRF("MPC SHA256 output shares don't match Halevi-Micali commitment");
    return -1;
  }

  return 0;
}

int mpc_hm_verify(UniversalHash *H, ZkBooCommit *a, ZkBooOpen *z, const uint8_t y[SHA256_DIGEST_LENGTH], int e) {

  if (verify_commit(a, z, y, e) != 0) {
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
  RVec r[2] = {z->ve->x, z->ve1->x};

  if (mpc_inner_prod_verify(H, m[0], r, a->y2p[0], e) != 0) {
    return -1;
  }

  return 0;
}
