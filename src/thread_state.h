#pragma once
#include "shared.h"

typedef struct ProverThreadState {
  // Shares reused each repetion of the zk-proof
  RVec rShares[3];
  uint32_t msgShares[MSG_WORDS][3];

  // Randomness tapes (3 pointers into one block)
  uint8_t *rand_block;
  uint8_t *randomness[3];

  // 3 views in one contiguous block
  View *views_block;
  View *views[3];

  // Hash contexts
  EVP_MD_CTX *ctx_chal; // used with EVP_MD_CTX_copy_ex + H3
  EVP_MD_CTX *ctx_hash; // used by HH() inside hash_views()

  // Serialization buffer per thread
  unsigned char *bufWrite;
  size_t bufSize;
} ProverThreadState;

typedef struct VerifierThreadState {
  // Shares reused each repetion of the zk-proof
  ZkBooCommit a;
  ZkBooOpen z;
  uint32_t y[8];

  // Hash contexts
  EVP_MD_CTX *ctx_chal; // used with EVP_MD_CTX_copy_ex + H3

  // Serialization buffer per thread
  unsigned char *bufWrite;
  size_t bufSize;
} VerifierThreadState;

int prover_thread_state_init(ProverThreadState *st, size_t bufSize);

void prover_thread_state_cleanup(ProverThreadState *st);

int verifier_thread_state_init(VerifierThreadState *st, size_t bufSize);

void verifier_thread_state_cleanup(VerifierThreadState *st);
