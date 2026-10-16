#include "hm.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const size_t message_bit_len = 2;
  enum { COUNT = 1 };
  const uint8_t messages[COUNT] = {0x03}; // Two message bits, LSB-first.
  hm_commit_sizes_t sizes = {0};
  hm_context_t *sender = NULL;
  hm_context_t *receiver = NULL;
  uint8_t *matrix = NULL;
  uint8_t *commitments = NULL;
  uint8_t *openings = NULL;
  int ret = 1;

  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    fprintf(stderr, "invalid message length\n");
    goto cleanup;
  }
  matrix = malloc(sizes.toeplitz_matrix_len);
  commitments = malloc(COUNT * sizes.commitment_len);
  openings = malloc(COUNT * sizes.opening_len);
  if (!matrix || !commitments || !openings) {
    fprintf(stderr, "allocation failed\n");
    goto cleanup;
  }
  // Sample one public matrix for the entire batch.
  if (hm_context_create(message_bit_len, &sender) != 0) {
    fprintf(stderr, "context creation failed\n");
    goto cleanup;
  }
  for (size_t i = 0; i < COUNT; i++) {
    if (hm_commit(sender, &messages[i], commitments + i * sizes.commitment_len,
                  sizes.commitment_len, openings + i * sizes.opening_len,
                  sizes.opening_len) != 0) {
      fprintf(stderr, "commit failed at index %zu\n", i);
      goto cleanup;
    }
  }

  // Send the matrix once, with the commitments. Each opening is sent later.
  if (hm_context_export_matrix(sender, matrix, sizes.toeplitz_matrix_len) !=
          0 ||
      hm_context_from_matrix(message_bit_len, matrix, sizes.toeplitz_matrix_len,
                             &receiver) != 0) {
    fprintf(stderr, "matrix transfer failed\n");
    goto cleanup;
  }
  for (size_t i = 0; i < COUNT; i++) {
    if (hm_verify(receiver, &messages[i],
                  commitments + i * sizes.commitment_len, sizes.commitment_len,
                  openings + i * sizes.opening_len, sizes.opening_len) != 0) {
      fprintf(stderr, "verification failed at index %zu\n", i);
      goto cleanup;
    }
  }
  printf("Created and verified %d two-bit commitments\n", COUNT);
  printf("shared matrix: %zu bytes\n", sizes.toeplitz_matrix_len);
  printf("commitments: %zu bytes\n", COUNT * sizes.commitment_len);
  printf("openings: %zu bytes\n", COUNT * sizes.opening_len);
  ret = 0;

cleanup:
  hm_context_free(receiver);
  hm_context_free(sender);
  free(matrix);
  free(commitments);
  free(openings);
  return ret;
}
