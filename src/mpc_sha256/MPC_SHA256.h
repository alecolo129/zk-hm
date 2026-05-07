#ifndef MPC_SHA_256_H_
#define MPC_SHA_256_H_

#include "shared.h"
#include <stdbool.h>

#define CH(e, f, g) ((e & f) ^ ((~e) & g))

void generate_randomness(unsigned int numRounds,
                         unsigned char keys[numRounds][3][16],
                         unsigned char *randomness[numRounds][3]);

int secretShare(unsigned char *input, int numBytes,
                unsigned char output[3][numBytes]);

void commit(unsigned char shares[3][L_BYTES],
            unsigned char *randomness[3], unsigned char rs[3][4],
            View views[3]);

void commit2(unsigned char shares[3][L_BYTES],
             unsigned char *randomness[3], View2 views[3]);

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4],
        View views[3]);

z2 prove2(int e, unsigned char keys[3][16], unsigned char rs[3][4],
          View2 views[3]);
#endif
