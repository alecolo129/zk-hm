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
#include <bits/time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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

static inline void pick_universal_hash(UniversalHash *h, const uint8_t keyA[16],
                                       const uint8_t rBytes[L_BYTES],
                                       const uint8_t msg[MSG_BYTES]) {
  uint32_t rWords[L_WORDS] = {0};
  bytes_to_words(rWords, rBytes, L_BYTES);
  generate_H(h->A, h->b, keyA, msg, rWords);
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

  if (test_randomness() != 0) {
    return -1;
  }

  uint8_t msg[MSG_WORDS * 4] = {0}; // 32-bit alligned
  msg[0] ^= (bit & 1);

  uint8_t rBytes[L_BYTES];
  RAND_bytes(rBytes, L_BYTES); // take random r in {0,1}^L

  /*
   * Return the HM opening randomness r to the caller.
   */
  if (hm_buffer_copy(opening_out, rBytes, sizeof(rBytes)) != 0) {
    LOG_ERRF("Could not copy opening into output buffer");
    goto cleanup;
  }

  uint8_t rs[NUM_ROUNDS][3][4]; // randomness internal commitments to views
  uint8_t keys[NUM_ROUNDS][3]
              [16]; // PRG keys to generate randomness for MPC protocol
  uint8_t keyH[16]; // key to generate universal hash function

  // Generating keys
  generate_keys_and_rs(keys, keyH, rs);
  UniversalHash h;
  pick_universal_hash(&h, keyH, rBytes, msg); // pick universal hash function
  if (serialize_universal_hash(commitment_out, keyH, &h, rBytes) != 0) {
    goto cleanup;
  }

  FILE *file = fopen(proof_file_path, "wb");
  if (!file) {
    goto cleanup;
  }

  // Initialise shared context
  EVP_MD_CTX *base_ctx = setupSHA256();
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
      share_secrets(st.rShares, st.msgShares, rBytes, msg);
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
      generate_challenge(&a, &e, st.ctx_chal);

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

  UniversalHash h;
  FILE *file = fopen(proof_file_path, "rb");
  if (!file) {
    LOG_ERRF("Unable to open proof file!");
    goto fail;
  }

  if (read_universal_hash(commitment, commitment_len, &h) != 0) {
    LOG_ERRF("Unable to parse proof!");
    goto fail;
  }

  // Expend universal hash from key
  expand_A(h.A, h.keyA);

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

      reconstruct(st.a.yp[0], st.a.yp[1], st.a.yp[2], st.y);

      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      H3(st.ctx_chal, st.y, &st.a, 1, &e);
      if (mpc_hm_verify(&h, &st.a, &st.z, e) != 0) {
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

int hm_bit_open(uint8_t bit, const uint8_t *commitment, size_t commitment_len,
                const uint8_t *opening, size_t opening_len) {
  if (!opening || opening_len != L_BYTES) {
    LOG_ERRF("Invalid sizes");
    return -1;
  }

  if (bit != 0 && bit != 1) {
    LOG_ERRF("Must commit to bit");
    return -1;
  }

  UniversalHash h;
  uint8_t y[SHA256_DIGEST_LENGTH];
  if (read_universal_hash_and_vector_commit(commitment, commitment_len, &h,
                                            y) != 0) {
    LOG_ERRF("Cannot read commitment");
    return -1;
  }

  // verify committed vector is valid for opening
  uint8_t y_rec[SHA256_DIGEST_LENGTH];
  SHA256(opening, opening_len, y_rec);
  if (memcmp(y, y_rec, SHA256_DIGEST_LENGTH) != 0) {
    LOG_ERRF("Commitment to opening did not verify");
    return -1;
  }

  // expend universal hash from key
  expand_A(h.A, h.keyA);

  // H(r) = Ar + b
  uint32_t acc = 0;
  const uint8_t *A = (uint8_t *)h.A;
  for (int i = 0; i < L_BYTES; i++) {
    acc ^= A[i] & opening[i];
  }
  acc = __builtin_parity(acc);
  acc ^= h.b[0];

  // commit verifies iff H(r) = m
  return (acc == bit) ? 0 : -1;
}
