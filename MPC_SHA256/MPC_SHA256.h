#ifndef MPC_SHA_256_H_
#define MPC_SHA_256_H_

#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CH(e, f, g) ((e & f) ^ ((~e) & g))

void generate_randomness(unsigned int numRounds,
                         unsigned char keys[numRounds][3][16],
                         unsigned char *randomness[numRounds][3]);

int secretShare(unsigned char *input, int numBytes,
                unsigned char output[3][numBytes]);

int mpc_sha256(unsigned char *results[3], unsigned char *inputs[3], int numBits,
               unsigned char *randomness[3], View views[3], int *countY);

a commit(int numBytes, unsigned char shares[3][numBytes],
         unsigned char *randomness[3], unsigned char rs[3][4], View views[3]);

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4],
        View views[3]);

#endif
