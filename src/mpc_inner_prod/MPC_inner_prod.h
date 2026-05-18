#include "shared.h"
#include <stdbool.h>
#include <stdint.h>

// *********** TODO: remove/specialize for bit commits ************************
void mpc_inner_prod_prover(const UniversalHash *h, const uint32_t m[3],
                           const uint32_t r[L_WORDS][3], uint32_t y[3]);

bool mpc_inner_prod_verify(const UniversalHash *h, const uint32_t m[2],
                           const uint32_t r[L_WORDS][2], const uint32_t y[3],
                           const uint32_t e);
// ****************************************************************************

void mpc_universal_hash_prover(const UniversalHash *h,
                               const uint32_t m[MSG_WORDS][3],
                               const uint32_t r[L_WORDS][3],
                               uint32_t y[MSG_WORDS][3]);

bool mpc_universal_hash_verifier(const UniversalHash *h,
                                 const uint32_t m[MSG_WORDS][2],
                                 const uint32_t r[L_WORDS][2],
                                 const uint32_t y[MSG_WORDS][3],
                                 const uint32_t e);

void expand_A(uint32_t A[A_WORDS], const uint8_t keyA[16]);

void generate_H(uint32_t A[A_WORDS], uint8_t b[MSG_BYTES],
                const uint8_t keyH[16], const uint8_t m[MSG_BYTES],
                const uint32_t r[L_WORDS]);