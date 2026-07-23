#include "hm.h"
#include "hm_buffer.h"
#include "mpc_core_funcs.h"
#include "mpc_halevi_micali.h"
#include "mpc_universal_hash.h"
#include "omp.h"
#include "prg.h"
#include "random_oracle.h"
#include "shared.h"
#include "thread_state.h"
#include "utils.h"
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: consider adjusting this value
#define MAX_MSG_BITLEN 10000000

static inline int test_randomness() {
  uint8_t garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    LOG_ERRF("RAND_bytes failed crypto, aborting\n");
    return -1;
  }
  return 0;
}

typedef struct {
  size_t message_byte_len;
  size_t opening_len;
  size_t l_words;
  size_t a_words;
  size_t commitment_len;
} HmCommitLayout;

static inline size_t ceil_div_size(size_t value, size_t divisor) {
  return value / divisor + (value % divisor != 0);
}

static int compute_sizes(size_t message_bit_len, HmCommitLayout *layout) {
  if (!layout || message_bit_len == 0 || message_bit_len > MAX_MSG_BITLEN) {
    return -1;
  }

  layout->message_byte_len = ceil_div_size(message_bit_len, 8u);

  size_t min_l_bits = 4u * (size_t)K + 2u * message_bit_len + 4u;
  layout->opening_len = ceil_div_size(min_l_bits, 8u);

  size_t l_bits = layout->opening_len * 8u;
  layout->l_words = ceil_div_size(l_bits, 32u);

  size_t max_base_word = (message_bit_len - 1u) / 32u;
  layout->a_words = max_base_word + layout->l_words + 1u;

  layout->commitment_len =
      16u + layout->message_byte_len + SHA256_DIGEST_LENGTH;
  return 0;
}

int hm_commit_get_sizes(size_t message_bit_len, hm_commit_sizes_t *sizes_out) {
  if (!sizes_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }

  sizes_out->commitment_len = 0;
  sizes_out->opening_len = 0;

  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0) {
    LOG_ERRF("invalid message bit length\n");
    return -1;
  }

  sizes_out->commitment_len = layout.commitment_len;
  sizes_out->opening_len = layout.opening_len;
  return 0;
}

int hm_commit(const uint8_t *message, size_t message_bit_len,
              uint8_t *commitment, size_t commitment_capacity, uint8_t *opening,
              size_t opening_capacity) {
  if (!message || !commitment || !opening) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }

  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0 ||
      commitment_capacity < layout.commitment_len ||
      opening_capacity < layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }

  // Allocate scratch buffers. The commitment and opening are caller-owned.
  uint32_t *A = malloc(layout.a_words * sizeof(uint32_t));
  uint32_t *r_words = malloc(layout.l_words * sizeof(uint32_t));
  if (!A || !r_words) {
    LOG_ERRF("malloc failure\n");
    goto fail;
  }

  uint8_t *keyA = commitment;
  uint8_t *b = commitment + 16u;
  uint8_t *digest = commitment + 16u + layout.message_byte_len;

  // TODO: should we directly pick the matrix instead?
  // pick UH key and r vector
  if (RAND_bytes(keyA, 16u) != 1 ||
      RAND_bytes(opening, layout.opening_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    goto fail;
  }

  // generate H from key
  expand_A(A, layout.a_words, keyA);
  universal_hash_load_words(r_words, opening, layout.opening_len,
                            layout.l_words);
  universal_hash_compute_b(b, A, r_words, layout.l_words, message,
                           message_bit_len);

  // compute H(r)
  SHA256(opening, layout.opening_len, digest);

  free(A);
  free(r_words);
  return 0;

fail:
  free(A);
  free(r_words);
  return -1;
}

int hm_verify(const uint8_t *message, size_t message_bit_len,
              const uint8_t *commitment, size_t commitment_len,
              const uint8_t *opening, size_t opening_len) {
  if (!message || !commitment || !opening || message_bit_len == 0) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }

  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0 ||
      commitment_len != layout.commitment_len ||
      opening_len != layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }

  const uint8_t *keyA = commitment;
  const uint8_t *b = commitment + 16u;
  const uint8_t *digest = commitment + 16u + layout.message_byte_len;

  // verify hash of r
  uint8_t digest_rec[SHA256_DIGEST_LENGTH];
  SHA256(opening, opening_len, digest_rec);
  if (memcmp(digest, digest_rec, SHA256_DIGEST_LENGTH) != 0) {
    LOG_ERRF("verification failed\n");
    return -1;
  }

  uint32_t *A = malloc(layout.a_words * sizeof(uint32_t));
  uint32_t *r_words = malloc(layout.l_words * sizeof(uint32_t));
  if (!A || !r_words) {
    LOG_ERRF("malloc failure\n");
    free(A);
    free(r_words);
    return -1;
  }

  // verify universal hash
  expand_A(A, layout.a_words, keyA);
  universal_hash_load_words(r_words, opening, opening_len, layout.l_words);
  int ret = universal_hash_verify_message(message, message_bit_len, b, A,
                                          r_words, layout.l_words);

  free(A);
  free(r_words);
  return ret;
}

static inline void pick_universal_hash(UniversalHash *h, const uint8_t keyA[16],
                                       const RVec *r,
                                       const uint8_t msg[MSG_BYTES]) {
  generate_H(h->A, h->b, keyA, msg, r);
}

static inline void hash_views(EVP_MD_CTX *ctx, uint8_t keys[3][16],
                              uint8_t rs[3][4], View *localViews[3],
                              ZkBooCommit *as) {
  uint8_t hash1[SHA256_DIGEST_LENGTH];
  HH(ctx, keys[0], localViews[0], rs[0], hash1);
  memcpy(as->h[0], &hash1, 32);
  HH(ctx, keys[1], localViews[1], rs[1], hash1);
  memcpy(as->h[1], &hash1, 32);
  HH(ctx, keys[2], localViews[2], rs[2], hash1);
  memcpy(as->h[2], &hash1, 32);
}

int hm_bit_commit(uint8_t bit, const char *proof_file_path,
                  hm_buffer_t *commitment_out, hm_buffer_t *opening_out) {
  FILE *file = NULL;
  EVP_MD_CTX *base_ctx = NULL;

  if (test_randomness() != 0) {
    return -1;
  }

  uint8_t msg[MSG_WORDS * 4] = {0}; // 32-bit alligned
  msg[0] ^= (bit & 1);

  RVec r;
  if (RAND_bytes((uint8_t *)r.words, sizeof(r.words)) !=
      1) { // take random r in {0,1}^L
    goto cleanup;
  }
  rvec_normalize(&r);

  /*
   * Return the HM opening randomness r to the caller.
   */
  if (hm_buffer_copy(opening_out, rvec_const_bytes(&r), L_BYTES) != 0) {
    LOG_ERRF("Could not copy opening into output buffer");
    goto cleanup;
  }

  uint8_t rs[NUM_ROUNDS][3][4]; // randomness internal commitments to views
  uint8_t keys[NUM_ROUNDS][3]
              [16]; // PRG keys to generate randomness for MPC protocol
  uint8_t keyH[16]; // key to generate universal hash function

  // Generating keys
  generate_keys_and_rs(keys, keyH, rs);

  // Generate halevi-micali commitment
  UniversalHash h;
  pick_universal_hash(&h, keyH, &r, msg); // pick universal hash function
  if (write_hm_commitment(commitment_out, keyH, &h, &r) != 0) {
    goto cleanup;
  }

  // Open proof file
  file = fopen(proof_file_path, "wb");
  if (!file) {
    goto cleanup;
  }

  // Initialise shared context
  base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, h.b, sizeof(h.b));

  size_t buffSize = sizeof(ZkBooCommit) + sizeof(ZkBooOpenDisk);

  atomic_int error = 0;
#pragma omp parallel
  {
    ProverThreadState st;
    if (prover_thread_state_init(&st, buffSize) != 0) {
      LOG_ERRF("Thread init failed (malloc/ctx).");
      atomic_store(&error, 1);
    }

#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&error)) {
        continue;
      }

      // Sharing secrets
      share_secrets(st.rShares, st.msgShares, &r, msg);
      // Generating randomness i.e., random tapes
      generate_randomness(keys[k], st.randomness);

      // Running HM commitment
      ZkBooCommit a;
      mpc_hm_prove(st.views, &a, st.randomness, rs[k], &h, st.rShares,
                   st.msgShares);
      // Committing
      hash_views(st.ctx_hash, keys[k], rs[k], st.views, &a);

      // Generating challenge (determines which 2 of the 3 views must be
      // opened).
      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      generate_challenge(st.ctx_chal, &e, &a, y_const_bytes(commitment_out));

      // Generate opening
      ZkBooOpen z;
      open(&z, e, keys[k], rs[k], st.views);

      // Write zk proof
      if (serialize_zk_proof_at(file, st.bufWrite, buffSize, k, &a, &z) != 0) {
        atomic_store(&error, 1);
        LOG_ERRF("Failed to serialize zk proof!\n");
      }
    }

    // Release thread state
    prover_thread_state_cleanup(&st);
  }

  EVP_MD_CTX_free(base_ctx);
  fclose(file);

  return error ? -1 : 0;

cleanup:
  if (file) {
    fclose(file);
  }

  if (base_ctx) {
    EVP_MD_CTX_free(base_ctx);
  }

  hm_buffer_free(commitment_out);
  hm_buffer_free(opening_out);

  return -1;
}

int hm_bit_verify(const uint8_t *commitment, size_t commitment_len,
                  const char *proof_file_path) {

  if (test_randomness() != 0) {
    return -1;
  }

  if (!commitment || commitment_len == 0 || !proof_file_path) {
    return -1;
  }

  FILE *file = fopen(proof_file_path, "rb");
  if (!file) {
    LOG_ERRF("Unable to open proof file!");
    goto fail;
  }

  UniversalHash h;
  uint8_t y[SHA256_DIGEST_LENGTH];
  if (read_hm_commitment(commitment, commitment_len, &h, y) != 0) {
    LOG_ERRF("Cannot read commitment");
    goto fail;
  }

  // Expend universal hash from key
  expand_A(h.A, A_WORDS, h.keyA);

  // Setup hash context
  EVP_MD_CTX *base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, h.b, sizeof(h.b));

  atomic_int error = 0;
#pragma omp parallel
  {
    // Init thread state
    VerifierThreadState st;
    ssize_t bufSize =
        sizeof(ZkBooCommit) + sizeof(ZkBooOpen) + 2 * sizeof(View);
    if (verifier_thread_state_init(&st, bufSize) != 0) {
      LOG_ERRF("Thread init failed (malloc/ctx).");
      atomic_store(&error, 1);
    }

    // Pack into one contiguous buffer to write once

#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&error)) {
        continue;
      }

      if (read_zk_proof_at(file, st.bufWrite, bufSize, k, &st.a, &st.z) != 0) {
        atomic_store(&error, 1);
      }

      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      H3(st.ctx_chal, y, &st.a, 1, &e);
      if (mpc_hm_verify(&h, &st.a, &st.z, y, e) != 0) {
        LOG_ERRF("Repetition #%d failed to verify!", k);
        atomic_store(&error, 1);
      }
    }

    // Clear state
    verifier_thread_state_cleanup(&st);
  }

  if (base_ctx)
    EVP_MD_CTX_free(base_ctx);
  fclose(file);
  return (error) ? -1 : 0;

fail:
  if (file)
    fclose(file);
  return -1;
}
