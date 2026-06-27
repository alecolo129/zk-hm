#pragma once
#include "shared.h"
#include <stdbool.h>

void mpc_hm_prove(View *localViews[3], ZkBooCommit *as,
                              uint8_t *randomness[3], uint8_t rs[3][4],
                              const UniversalHash *h,
                              RVec rShares[3],
                              const uint32_t msgShares[MSG_WORDS][3]);


int mpc_hm_verify(UniversalHash *H, ZkBooCommit *a, ZkBooOpen *z, int e);
