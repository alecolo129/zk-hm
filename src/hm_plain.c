#include "hm_plain.h"
#include "hm_parameters.h"
#include "hm_platform.h"
#include "universal_hash.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

// TODO: consider adjusting this value
#define MAX_MSG_BITLEN 10000000

typedef struct {
  size_t message_byte_len;
  size_t l_bits;
  size_t opening_len;
  size_t l_words;
  size_t toeplitz_matrix_bit_len;
  size_t toeplitz_matrix_len;
  size_t toeplitz_matrix_words;
  size_t commitment_len;
} HmCommitLayout;

struct hm_context_t {
  size_t message_bit_len;
  HmCommitLayout layout;
  uint32_t *A;
  uint32_t *r_words;
};

static inline size_t ceil_div_size(size_t value, size_t divisor) {
  return value / divisor + (value % divisor != 0);
}

static int compute_sizes(size_t message_bit_len, HmCommitLayout *layout) {
  if (message_bit_len == 0 || message_bit_len > MAX_MSG_BITLEN) {
    return -1;
  }

  layout->message_byte_len = ceil_div_size(message_bit_len, 8u);
  layout->l_bits =
      4u * (size_t)HM_BINDING_SECURITY_BITS + 2u * message_bit_len + 4u;
  layout->opening_len = ceil_div_size(layout->l_bits, 8u);
  layout->l_words = ceil_div_size(layout->l_bits, 32u);
  layout->toeplitz_matrix_bit_len = layout->l_bits + message_bit_len - 1u;
  layout->toeplitz_matrix_len =
      ceil_div_size(layout->toeplitz_matrix_bit_len, 8u);

  // Word windows read one extra word
  size_t max_base_word = (message_bit_len - 1u) / 32u;
  layout->toeplitz_matrix_words = max_base_word + layout->l_words + 1u;
  layout->commitment_len = layout->message_byte_len + SHA256_DIGEST_LENGTH;
  return 0;
}

static inline uint8_t last_byte_mask(size_t bit_len) {
  size_t used_bits = bit_len % 8u;
  return used_bits == 0u ? UINT8_MAX : (uint8_t)((1u << used_bits) - 1u);
}

int hm_commit_get_sizes(size_t message_bit_len, hm_commit_sizes_t *sizes_out) {
  if (!sizes_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *sizes_out = (hm_commit_sizes_t){0};
  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0) {
    LOG_ERRF("invalid message bit length\n");
    return -1;
  }
  sizes_out->commitment_len = layout.commitment_len;
  sizes_out->opening_len = layout.opening_len;
  sizes_out->toeplitz_matrix_len = layout.toeplitz_matrix_len;
  return 0;
}

void hm_context_free(hm_context_t *ctx) {
  if (ctx) {
    if (ctx->r_words) {
      OPENSSL_clear_free(ctx->r_words, ctx->layout.l_words * sizeof(uint32_t));
    }
    free(ctx->A);
    free(ctx);
  }
}

static int context_allocate(size_t message_bit_len, hm_context_t **ctx_out) {
  if (!ctx_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *ctx_out = NULL;
  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0) {
    LOG_ERRF("invalid message bit length\n");
    return -1;
  }
  hm_context_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) {
    LOG_ERRF("allocation failure\n");
    return -1;
  }
  ctx->message_bit_len = message_bit_len;
  ctx->layout = layout;
  ctx->A = calloc(layout.toeplitz_matrix_words, sizeof(uint32_t));
  ctx->r_words = OPENSSL_zalloc(layout.l_words * sizeof(uint32_t));
  if (!ctx->A || !ctx->r_words) {
    LOG_ERRF("allocation failure\n");
    hm_context_free(ctx);
    return -1;
  }
  *ctx_out = ctx;
  return 0;
}

int hm_context_create(size_t message_bit_len, hm_context_t **ctx_out) {
  if (context_allocate(message_bit_len, ctx_out) != 0) {
    return -1;
  }
  hm_context_t *ctx = *ctx_out;
  // The repository targets little-endian hosts, so word storage is also the
  // canonical byte encoding. Sample the full diagonal description once.
  uint8_t *matrix = (uint8_t *)ctx->A;
  if (RAND_bytes(matrix, (int)ctx->layout.toeplitz_matrix_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    hm_context_free(ctx);
    *ctx_out = NULL;
    return -1;
  }
  matrix[ctx->layout.toeplitz_matrix_len - 1u] &=
      last_byte_mask(ctx->layout.toeplitz_matrix_bit_len);
  return 0;
}

int hm_context_from_matrix(size_t message_bit_len, const uint8_t *matrix,
                           size_t matrix_len, hm_context_t **ctx_out) {
  if (!ctx_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *ctx_out = NULL;
  HmCommitLayout layout;
  if (!matrix || compute_sizes(message_bit_len, &layout) != 0 ||
      matrix_len != layout.toeplitz_matrix_len) {
    LOG_ERRF("invalid inputs or sizes\n");
    return -1;
  }
  if (matrix[matrix_len - 1u] &
      ~last_byte_mask(layout.toeplitz_matrix_bit_len)) {
    LOG_ERRF("non-canonical matrix description\n");
    return -1;
  }
  if (context_allocate(message_bit_len, ctx_out) != 0) {
    return -1;
  }
  memcpy((*ctx_out)->A, matrix, matrix_len);
  return 0;
}

int hm_context_export_matrix(const hm_context_t *ctx, uint8_t *matrix_out,
                             size_t matrix_capacity) {
  if (!ctx || !matrix_out ||
      matrix_capacity < ctx->layout.toeplitz_matrix_len) {
    LOG_ERRF("invalid inputs or sizes\n");
    return -1;
  }
  memcpy(matrix_out, ctx->A, ctx->layout.toeplitz_matrix_len);
  return 0;
}

int hm_commit(hm_context_t *ctx, const uint8_t *message, uint8_t *commitment,
              size_t commitment_capacity, uint8_t *opening,
              size_t opening_capacity) {
  if (!ctx || !message || !commitment || !opening) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }
  if (commitment_capacity < ctx->layout.commitment_len ||
      opening_capacity < ctx->layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }
  const HmCommitLayout *layout = &ctx->layout;
  uint8_t *r = (uint8_t *)ctx->r_words;
  if (RAND_bytes(r, (int)layout->opening_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    return -1;
  }
  r[layout->opening_len - 1u] &= last_byte_mask(layout->l_bits);
  // Remaining bytes in the padded last word stay zero between calls.
  memcpy(opening, r, layout->opening_len);
  universal_hash_compute_b(commitment, ctx->A, ctx->r_words, layout->l_words,
                           message, ctx->message_bit_len);
  if (!SHA256(r, layout->opening_len, commitment + layout->message_byte_len)) {
    LOG_ERRF("SHA256 failure\n");
    return -1;
  }
  return 0;
}

int hm_verify(hm_context_t *ctx, const uint8_t *message,
              const uint8_t *commitment, size_t commitment_len,
              const uint8_t *opening, size_t opening_len) {
  if (!ctx || !message || !commitment || !opening) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }
  if (commitment_len != ctx->layout.commitment_len ||
      opening_len != ctx->layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }
  const HmCommitLayout *layout = &ctx->layout;
  if ((opening[opening_len - 1u] & ~last_byte_mask(layout->l_bits)) ||
      (commitment[layout->message_byte_len - 1u] &
       ~last_byte_mask(ctx->message_bit_len))) {
    LOG_ERRF("non-canonical commitment or opening\n");
    return -1;
  }
  uint8_t digest[SHA256_DIGEST_LENGTH];
  if (!SHA256(opening, opening_len, digest) ||
      memcmp(commitment + layout->message_byte_len, digest, sizeof(digest)) !=
          0) {
    LOG_ERRF("verification failed\n");
    return -1;
  }
  memcpy(ctx->r_words, opening, opening_len);
  int ret =
      universal_hash_verify_message(message, ctx->message_bit_len, commitment,
                                    ctx->A, ctx->r_words, layout->l_words);
  if (ret != 0) {
    LOG_ERRF("verification failed\n");
  }
  return ret;
}
