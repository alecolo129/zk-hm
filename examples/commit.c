#include "hm.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void print_msg(int msg, size_t msg_len) {
  printf("Committed to msg ");
  int i = sizeof(int) * 8;
  while (sizeof(int) * 8 - i < msg_len) {
    printf("%d", (msg & 1) ? 1 : 0);
    msg >>= 1;
    i--;
  }
  printf("\n");
}

int main(void) {
  // commit to msg 0b11 (little-endian)
  const uint8_t msg = 0x03;
  const size_t message_bit_len = 2;

  hm_commit_sizes_t sizes = {0};
  uint8_t *toeplitz_matrix = NULL;
  uint8_t *commitment = NULL;
  uint8_t *opening = NULL;
  int ret = 1;

  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    fprintf(stderr, "hm_commit_get_sizes failed\n");
    goto cleanup;
  }

  commitment = malloc(sizes.commitment_len);
  opening = malloc(sizes.opening_len);
  toeplitz_matrix = malloc(sizes.toeplitz_matrix_len);
  if (!commitment || !opening || !toeplitz_matrix) {
    fprintf(stderr, "allocation failed\n");
    goto cleanup;
  }

  const size_t toeplitz_matrix_len = sizes.toeplitz_matrix_len;
  if (hm_pick_universal_hash(message_bit_len, toeplitz_matrix, toeplitz_matrix_len) != 0) {
    printf("hm_pick_universal_hash failed\n");
    goto cleanup;
  }

  if (hm_commit(toeplitz_matrix, toeplitz_matrix_len, &msg, message_bit_len,
                commitment, sizes.commitment_len, opening,
                sizes.opening_len) != 0) {
    fprintf(stderr, "hm_commit failed\n");
    goto cleanup;
  }

  print_msg(msg, message_bit_len);
  printf("commitment: %zu bytes\n", sizes.commitment_len);
  printf("opening: %zu bytes\n", sizes.opening_len);

  if (hm_verify(toeplitz_matrix, toeplitz_matrix_len, &msg, message_bit_len,
                commitment, sizes.commitment_len, opening,
                sizes.opening_len) != 0) {
    fprintf(stderr, "hm_verify failed\n");
    goto cleanup;
  }

  printf("Commitment verified successfully\n");
  ret = 0;

cleanup:
  free(commitment);
  free(opening);
  return ret;
}
