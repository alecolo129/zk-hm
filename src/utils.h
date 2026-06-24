#pragma once
#include "hm.h"
#include "shared.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static inline void bytes_to_words(uint32_t *dst, const uint8_t *src,
                                  size_t n_bytes) {
  size_t n_words = n_bytes / 4;

  memcpy(dst, src, n_words * sizeof(uint32_t));

  size_t rem = n_bytes % 4;
  if (rem != 0) {
    dst[n_words] = 0;
    memcpy(&dst[n_words], src + 4 * n_words, rem);
  }
}

static inline int read_universal_hash(const uint8_t *commitment,
                                      size_t commitment_len, UniversalHash *H) {
  if (commitment_len != 16 + sizeof(H->b) + SHA256_DIGEST_LENGTH) {
    LOG_ERRF("Commitment length invalid");
    return -1;
  }
  memcpy(H->keyA, commitment, 16);
  memcpy(H->b, commitment + 16, sizeof(H->b));
  return 0;
}

static inline int
read_universal_hash_and_vector_commit(const uint8_t *commitment,
                                      size_t commitment_len, UniversalHash *H,
                                      uint8_t y[SHA256_DIGEST_LENGTH]) {
  if (commitment_len != 16 + sizeof(H->b) + SHA256_DIGEST_LENGTH) {
    LOG_ERRF("Commitment length invalid");
    return -1;
  }
  memcpy(H->keyA, commitment, 16);
  memcpy(H->b, commitment + 16, sizeof(H->b));
  memcpy(y, commitment + 16 + sizeof(H->b), SHA256_DIGEST_LENGTH);
  return 0;
}

static inline int serialize_universal_hash(hm_buffer_t *commitment_out,
                                           const uint8_t keyH[16],
                                           const UniversalHash *H,
                                           const uint8_t rBytes[L_BYTES]) {

  if (!keyH || !H || !commitment_out) {
    return -1;
  }

  commitment_out->len = 16 + sizeof(H->b) + SHA256_DIGEST_LENGTH;
  commitment_out->data = malloc(commitment_out->len);
  if (!commitment_out->data) {
    LOG_ERRF("malloc failure");
    return -1;
  }

  // Pack into one contiguous buffer to write once
  memcpy(commitment_out->data, keyH, 16);
  memcpy(commitment_out->data + 16, H->b, sizeof(H->b));
  SHA256(rBytes, L_BYTES, commitment_out->data + 16 + sizeof(H->b));
  return 0;
}

static inline int serialize_zk_proof_at(FILE *f, unsigned char *buf,
                                        size_t buffSize, int k,
                                        const ZkBooCommit *a_ptr,
                                        const ZkBooOpen *z_ptr) {

  size_t proofSize = sizeof(ZkBooCommit) + sizeof(ZkBooOpenDisk);
  if (buffSize < proofSize) {
    LOG_ERRF("Allocated buffer is %luB, required is %luB\n", buffSize,
             proofSize);
    return -1;
  }

  size_t bufIdx = 0;
  memcpy(buf, a_ptr, sizeof(*a_ptr));
  bufIdx += sizeof(*a_ptr);

  memcpy(buf + bufIdx, z_ptr->ke, sizeof(z_ptr->ke));
  bufIdx += sizeof(z_ptr->ke);
  memcpy(buf + bufIdx, z_ptr->ke1, sizeof(z_ptr->ke1));
  bufIdx += sizeof(z_ptr->ke1);

  memcpy(buf + bufIdx, z_ptr->re, sizeof(z_ptr->re));
  bufIdx += sizeof(z_ptr->re);
  memcpy(buf + bufIdx, z_ptr->re1, sizeof(z_ptr->re1));
  bufIdx += sizeof(z_ptr->re1);

  memcpy(buf + bufIdx, z_ptr->ve, sizeof(*z_ptr->ve));
  bufIdx += sizeof(*z_ptr->ve);
  memcpy(buf + bufIdx, z_ptr->ve1, sizeof(*z_ptr->ve1));
  bufIdx += sizeof(*z_ptr->ve1);

  int fd = fileno(f);
  off_t off = (off_t)k * proofSize;

  ssize_t nWrite = pwrite(fd, buf, proofSize, off);
  return (nWrite == (ssize_t)bufIdx) ? 0 : -1;
}

static inline int read_zk_proof_at(FILE *f, unsigned char *buf, size_t bufSize,
                                   int k, ZkBooCommit *a_ptr,
                                   ZkBooOpen *z_ptr) {
  size_t proofSize = sizeof(ZkBooCommit) + sizeof(ZkBooOpenDisk);
  if (bufSize < proofSize) {
    return -1;
  }

  // read buffer
  int fd = fileno(f);
  off_t off = (off_t)k * proofSize;
  ssize_t nRead = pread(fd, buf, proofSize, off);
  if (nRead != proofSize) {
    return -1;
  }

  size_t bufIdx = 0;
  memcpy(a_ptr, buf, sizeof(*a_ptr));
  bufIdx += sizeof(*a_ptr);

  memcpy(z_ptr->ke, buf + bufIdx, sizeof(z_ptr->ke));
  bufIdx += sizeof(z_ptr->ke);
  memcpy(z_ptr->ke1, buf + bufIdx, sizeof(z_ptr->ke1));
  bufIdx += sizeof(z_ptr->ke1);

  memcpy(z_ptr->re, buf + bufIdx, sizeof(z_ptr->re));
  bufIdx += sizeof(z_ptr->re);
  memcpy(z_ptr->re1, buf + bufIdx, sizeof(z_ptr->re1));
  bufIdx += sizeof(z_ptr->re1);

  // allocate views memory
  if (!z_ptr->ve || !z_ptr->ve1) {
    return -1;
  }

  memcpy(z_ptr->ve, buf + bufIdx, sizeof(View));
  bufIdx += sizeof(*z_ptr->ve);
  memcpy(z_ptr->ve1, buf + bufIdx, sizeof(View));
  bufIdx += sizeof(*z_ptr->ve1);

  return 0;
}
