#ifndef MPC_SHA256_VERIFIER_H_
#define MPC_SHA256_VERIFIER_H_
#include "shared.h"
#include "stdbool.h"

bool verify_hash(a *a, int e, z *z);

int verify(a *a, int e, z *z);

#endif
