#include "hm.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const size_t message_bit_len = 2;
  enum { COUNT = 100 };

  uint8_t messages[COUNT];
  for (size_t i = 0; i < COUNT; i++) {
    messages[i] = (uint8_t)(i & 0x03u);
  }

  hm_commit_sizes_t sizes = {0};
  uint8_t *matrix = NULL;
  uint8_t *commitments = NULL;
  uint8_t *openings = NULL;
  int ret = 1;

  // compute sizes for caller-owned buffers
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    fprintf(stderr, "invalid message length\n");
    goto cleanup;
  }

  /*
    Sender
  */

  hm_context_t *sender_ctx = NULL;

  matrix = malloc(sizes.toeplitz_matrix_len);
  commitments = malloc(COUNT * sizes.commitment_len);
  openings = malloc(COUNT * sizes.opening_len);
  if (!matrix || !commitments || !openings) {
    fprintf(stderr, "allocation failed\n");
    goto cleanup;
  }

  // sample one public matrix for the entire batch
  if (hm_context_create(message_bit_len, &sender_ctx) != 0) {
    fprintf(stderr, "context creation failed\n");
    goto cleanup;
  }

  // compute commmitments
  for (size_t i = 0; i < COUNT; i++) {
    if (hm_commit(sender_ctx, &messages[i],
                  commitments + i * sizes.commitment_len, sizes.commitment_len,
                  openings + i * sizes.opening_len, sizes.opening_len) != 0) {
      fprintf(stderr, "commit failed at index %zu\n", i);
      goto cleanup;
    }
  }

  // Send the matrix once, with the commitments
  // Openings are usually sent separately (e.g., selective opening)
  if (hm_context_export_matrix(sender_ctx, matrix, sizes.toeplitz_matrix_len) !=
      0) {
    fprintf(stderr, "matrix export failed\n");
    goto cleanup;
  }

  /*
    Receiver
  */

  hm_context_t *receiver_ctx = NULL;

  // init verifier's context from matrix
  if (hm_context_from_matrix(message_bit_len, matrix, sizes.toeplitz_matrix_len,
                             &receiver_ctx) != 0) {
    fprintf(stderr, "matrix import failed\n");
    goto cleanup;
  }

  // verify batch with openings
  for (size_t i = 0; i < COUNT; i++) {
    if (hm_verify(receiver_ctx, &messages[i],
                  commitments + i * sizes.commitment_len, sizes.commitment_len,
                  openings + i * sizes.opening_len, sizes.opening_len) != 0) {
      fprintf(stderr, "verification failed at index %zu\n", i);
      goto cleanup;
    }
  }

  printf("Created and verified %d two-bit commitments:\n", COUNT);
  printf("\t- shared matrix: %zu bytes\n", sizes.toeplitz_matrix_len);
  printf("\t- commitments: %zu bytes\n", COUNT * sizes.commitment_len);
  printf("\t- openings: %zu bytes\n", COUNT * sizes.opening_len);
  printf("Total sent: %zu bytes\n",
         sizes.toeplitz_matrix_len +
             COUNT * (sizes.commitment_len + sizes.opening_len));
  ret = 0;

cleanup:
  hm_context_free(receiver_ctx);
  hm_context_free(sender_ctx);
  free(matrix);
  free(commitments);
  free(openings);
  return ret;
}
