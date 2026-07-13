#include "hm.h"

#include <stdint.h>
#include <stdio.h>

void print_msg(int msg, ssize_t msg_len) {
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
  const ssize_t msg_bit_len = 2;

  hm_buffer_t commitment = {0};
  hm_buffer_t opening = {0};
  int ret = 1;

  if (hm_commit(&msg, msg_bit_len, &commitment, &opening) != 0) {
    fprintf(stderr, "hm_commit failed\n");
    goto cleanup;
  }

  print_msg(msg, msg_bit_len);
  printf("commitment: %zu bytes\n", commitment.len);
  printf("opening: %zu bytes\n", opening.len);

  if (hm_verify(&msg, msg_bit_len, commitment.data, commitment.len,
                opening.data, opening.len) != 0) {
    fprintf(stderr, "hm_verify failed\n");
    goto cleanup;
  }

  printf("Commitment verified successfully\n");
  ret = 0;

cleanup:
  hm_buffer_free(&commitment);
  hm_buffer_free(&opening);
  return ret;
}
