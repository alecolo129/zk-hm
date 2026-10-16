#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Required output sizes for a plain Halevi-Micali commitment, opening,
 * and Toeplitz matrix description.
 *
 * The matrix is provided separately and can be shared by a batch of
 * equally-sized messages.
 */
typedef struct hm_commit_sizes_t {
  size_t commitment_len;
  size_t opening_len;
  size_t toeplitz_matrix_len;
} hm_commit_sizes_t;

/**
 * Compute the output sizes required to commit to a bit string.
 *
 * @param[in] message_bit_len     The number of message bits to commit
 * @param[out] sizes_out          The required commitment, opening, and matrix
 * sizes
 *
 * @return Returns 0 if the sizes were computed successfully, or a non-zero
 * value if the input is invalid or the message length exceeds the maximum
 * supported length.
 */
int hm_commit_get_sizes(size_t message_bit_len, hm_commit_sizes_t *sizes_out);

/**
 * Reusable context holding the shared Toeplitz matrix and temporary storage.
 *
 * Release contexts with hm_context_free(). A context must not be used by
 * multiple callers concurrently.
 */
typedef struct hm_context_t hm_context_t;

/**
 * Create a context with a randomly sampled Toeplitz matrix.
 *
 * @param[in] message_bit_len     The number of message bits to commit
 * @param[out] ctx_out            The context allocated by the library
 *
 * @return Returns 0 if the context was created successfully, or a non-zero
 * value indicating failure.
 */
int hm_context_create(size_t message_bit_len, hm_context_t **ctx_out);

/**
 * Create a context from an existing Toeplitz matrix. The matrix is copied.
 *
 * @param[in] message_bit_len     The number of message bits to commit
 * @param[in] matrix              The exported Toeplitz matrix description
 * @param[in] matrix_len          The matrix description length, in bytes
 * @param[out] ctx_out            The context allocated by the library
 *
 * @return Returns 0 if the context was created successfully, or a non-zero
 * value indicating failure.
 */
int hm_context_from_matrix(size_t message_bit_len, const uint8_t *matrix,
                           size_t matrix_len, hm_context_t **ctx_out);

/**
 * Export the context's Toeplitz matrix to a caller-owned buffer.
 *
 * @param[in] ctx                 The Halevi-Micali context
 * @param[out] matrix_out         The buffer receiving the matrix description
 * @param[in] matrix_capacity     The available bytes in the output buffer
 *
 * @return Returns 0 if the matrix was exported successfully, or a non-zero
 * value indicating failure. The required buffer size is returned by
 * hm_commit_get_sizes().
 */
int hm_context_export_matrix(const hm_context_t *ctx, uint8_t *matrix_out,
                             size_t matrix_capacity);

/**
 * Free a context allocated by the library.
 *
 * @param[in] ctx                 The context to release. May be NULL.
 */
void hm_context_free(hm_context_t *ctx);

/**
 * Commit to a bit string of the length configured in the context, using
 * caller-owned output buffers. Each call samples a fresh opening.
 *
 * @param[in,out] ctx             The Halevi-Micali context
 * @param[in] message             The message bits. Bits are read LSB-first
 * @param[out] commitment         The buffer receiving the commitment
 * @param[in] commitment_capacity The available bytes in the commitment buffer
 * @param[out] opening            The buffer receiving the opening
 * @param[in] opening_capacity    The available bytes in the opening buffer
 *
 * @return Returns 0 if the commitment was computed successfully, or a non-zero
 * value indicating failure. On success, exactly the sizes returned by
 * hm_commit_get_sizes() are written. The library never frees the supplied
 * buffers. The message, commitment, and opening memory regions must not
 * overlap.
 */
int hm_commit(hm_context_t *ctx, const uint8_t *message, uint8_t *commitment,
              size_t commitment_capacity, uint8_t *opening,
              size_t opening_capacity);

/**
 * Verify the commitment against the input bit string and opening.
 *
 * @param[in,out] ctx             The Halevi-Micali context
 * @param[in] message             The message bits. Bits are read LSB-first
 * @param[in] commitment          The Halevi-Micali commitment
 * @param[in] commitment_len      The commitment length, in bytes
 * @param[in] opening             The Halevi-Micali opening
 * @param[in] opening_len         The opening length, in bytes
 *
 * @return Returns 0 if the message was successfully verified, or a non-zero
 * value indicating an error or failed verification.
 */
int hm_verify(hm_context_t *ctx, const uint8_t *message,
              const uint8_t *commitment, size_t commitment_len,
              const uint8_t *opening, size_t opening_len);

#ifdef __cplusplus
}
#endif
