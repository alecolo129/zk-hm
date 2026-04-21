#include "shared.h"
#include <stdbool.h>
#include <stdint.h>

void mpc_inner_prod(uint32_t shares[3], uint32_t r[L_WORDS][3],
                    uint32_t A[L_WORDS][3], unsigned char *randomness[3],
                    View views[3], int *countY);
