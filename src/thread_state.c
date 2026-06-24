#include "thread_state.h"
#include "random_oracle.h"
#include "shared.h"
#include "string.h"
#include <stdlib.h>

int prover_thread_state_init(ProverThreadState *st, size_t bufSize) {
  if (!st)
    return -1;
  memset(st, 0, sizeof(*st));

  st->bufSize = bufSize;

  // Allocate randomness block and set pointers
  st->rand_block = (uint8_t *)malloc(3u * RAND_BYTES);
  if (!st->rand_block)
    goto fail;
  st->randomness[0] = st->rand_block;
  st->randomness[1] = st->rand_block + RAND_BYTES;
  st->randomness[2] = st->rand_block + 2u * RAND_BYTES;

  // Allocate views block and set pointers
  st->views_block = (View *)malloc(3u * sizeof(View));
  if (!st->views_block)
    goto fail;
  st->views[0] = st->views_block;
  st->views[1] = st->views_block + 1;
  st->views[2] = st->views_block + 2;

  // Allocate write buffer (one per thread)
  st->bufWrite = (unsigned char *)malloc(bufSize);
  if (!st->bufWrite)
    goto fail;

  // Create contexts
  st->ctx_chal = EVP_MD_CTX_new();
  if (!st->ctx_chal)
    goto fail;

  st->ctx_hash = setupSHA256();
  if (!st->ctx_hash)
    goto fail;

  // Init shares to known values (not strictly necessary, but helps MSan/ASan)
  memset(st->rShares, 0, sizeof(st->rShares));
  memset(st->msgShares, 0, sizeof(st->msgShares));

  return 0;

fail:
  prover_thread_state_cleanup(st);
  return -1;
}

void prover_thread_state_cleanup(ProverThreadState *st) {
  if (!st)
    return;

  if (st->ctx_chal)
    EVP_MD_CTX_free(st->ctx_chal);
  if (st->ctx_hash)
    EVP_MD_CTX_free(st->ctx_hash);

  if (st->bufWrite) {
    free(st->bufWrite);
  }

  if (st->views_block) {
    OPENSSL_cleanse(st->views_block, 3u * sizeof(View));
    free(st->views_block);
  }

  if (st->rand_block) {
    OPENSSL_cleanse(st->rand_block, 3u * RAND_BYTES);
    free(st->rand_block);
  }

  // Wipe stack-resident shares as well (optional)
  OPENSSL_cleanse(st->rShares, sizeof(st->rShares));
  OPENSSL_cleanse(st->msgShares, sizeof(st->msgShares));

  // Reset to a known state
  memset(st, 0, sizeof(*st));
}

int verifier_thread_state_init(VerifierThreadState *st, size_t bufSize) {
  if (!st)
    return -1;
  memset(st, 0, sizeof(*st));

  st->bufSize = bufSize;

  // Allocate write buffer (one per thread)
  st->bufWrite = (unsigned char *)malloc(bufSize);
  if (!st->bufWrite)
    goto fail;

  st->z.ve = malloc(sizeof(View));
  if (!st->z.ve)
    goto fail;

  st->z.ve1 = malloc(sizeof(View));
  if (!st->z.ve1)
    goto fail;
  
  // Create contexts
  st->ctx_chal = EVP_MD_CTX_new();
  if (!st->ctx_chal)
    goto fail;

  return 0;
fail:
  verifier_thread_state_cleanup(st);
  return -1;
}

void verifier_thread_state_cleanup(VerifierThreadState *st) {
  if (!st)
    return;

  if (st->ctx_chal)
    EVP_MD_CTX_free(st->ctx_chal);

  if (st->z.ve)
    free(st->z.ve);

  if (st->z.ve1)
    free(st->z.ve1);

  if (st->bufWrite) {
    free(st->bufWrite);
  }

  // Reset to a known state
  memset(st, 0, sizeof(*st));
}
