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

static inline int test_randomness() {
  uint8_t garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    LOG_ERRF("RAND_bytes failed crypto, aborting\n");
    return -1;
  }
  return 0;
}

static inline size_t ceil_bits_to_bytes(size_t bits) {
  return (bits + 7) / 8;
}

static inline void compute_sizes(size_t message_bit_len,
                                 size_t *message_byte_len, size_t *opening_len,
                                 size_t *l_words, size_t *a_words,
                                 size_t *commitment_len) {
  *message_byte_len = ceil_bits_to_bytes(message_bit_len);

  size_t min_l_bits = 4u * K + 2u * message_bit_len + 4u;
  *opening_len = ceil_bits_to_bytes(min_l_bits);
  size_t l_bits = *opening_len * 8u;
  *l_words = (l_bits + 31u) / 32u;

  size_t max_base_word = (message_bit_len - 1u) / 32u;
  *a_words = max_base_word + *l_words + 1u;
  *commitment_len = 16u + *message_byte_len + SHA256_DIGEST_LENGTH;
}

int hm_commit(const uint8_t *message, size_t message_bit_len,
              hm_buffer_t *commitment_out, hm_buffer_t *opening_out) {
  if (!message || !commitment_out || !opening_out || message_bit_len == 0) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }

  commitment_out->data = NULL;
  commitment_out->len = 0;
  opening_out->data = NULL;
  opening_out->len = 0;

  // compute sizes
  size_t message_byte_len = 0;
  size_t opening_len = 0;
  size_t l_words = 0;
  size_t a_words = 0;
  size_t commitment_len = 0;
  compute_sizes(message_bit_len, &message_byte_len, &opening_len, &l_words,
                &a_words, &commitment_len);

  // allocate buffers
  uint32_t *A = malloc(a_words * sizeof(uint32_t));
  uint32_t *r_words = malloc(l_words * sizeof(uint32_t));
  commitment_out->data = malloc(commitment_len);
  opening_out->data = malloc(opening_len);
  if (!A || !r_words || !commitment_out->data || !opening_out->data) {
    LOG_ERRF("malloc failure\n");
    goto fail;
  }
  commitment_out->len = commitment_len;
  opening_out->len = opening_len;

  uint8_t *keyA = commitment_out->data;
  uint8_t *b = commitment_out->data + 16u;
  uint8_t *digest = commitment_out->data + 16u + message_byte_len;

  // pick UH key and r vector
  if (RAND_bytes(keyA, 16u) != 1 ||
      RAND_bytes(opening_out->data, opening_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    goto fail;
  }

  // generate H from key
  expand_A(A, a_words, keyA);
  universal_hash_load_words(r_words, opening_out->data, opening_len, l_words);
  universal_hash_compute_b(b, A, r_words, l_words, message, message_bit_len);
  
  // compute H(r)
  SHA256(opening_out->data, opening_len, digest);

  free(A);
  free(r_words);
  return 0;

fail:
  free(A);
  free(r_words);
  hm_buffer_free(commitment_out);
  hm_buffer_free(opening_out);
  return -1;
}

int hm_verify(const uint8_t *message, size_t message_bit_len,
            const uint8_t *commitment, size_t commitment_len,
            const uint8_t *opening, size_t opening_len) {
  if (!message || !commitment || !opening || message_bit_len == 0) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }

  size_t message_byte_len = 0;
  size_t expected_opening_len = 0;
  size_t l_words = 0;
  size_t a_words = 0;
  size_t expected_commitment_len = 0;
  compute_sizes(message_bit_len, &message_byte_len, &expected_opening_len,
                &l_words, &a_words, &expected_commitment_len);
  if (commitment_len != expected_commitment_len ||
      opening_len != expected_opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }

  const uint8_t *keyA = commitment;
  const uint8_t *b = commitment + 16u;
  const uint8_t *digest = commitment + 16u + message_byte_len;

  // verify hash of r
  uint8_t digest_rec[SHA256_DIGEST_LENGTH];
  SHA256(opening, opening_len, digest_rec);
  if (memcmp(digest, digest_rec, SHA256_DIGEST_LENGTH) != 0) {
    LOG_ERRF("verification failed\n");
    return -1;
  }

  uint32_t *A = malloc(a_words * sizeof(uint32_t));
  uint32_t *r_words = malloc(l_words * sizeof(uint32_t));
  if (!A || !r_words) {
    LOG_ERRF("malloc failure\n");
    free(A);
    free(r_words);
    return -1;
  }

  // verify universal hash
  expand_A(A, a_words, keyA);
  universal_hash_load_words(r_words, opening, opening_len, l_words);
  int ret =
      universal_hash_verify_message(message, message_bit_len, b, A, r_words,
                                    l_words);

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
