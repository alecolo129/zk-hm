CC = gcc
CFLAGS = -O3 -fopenmp -I $(HOME)/openssl-1.0.2/include
LDFLAGS = $(HOME)/openssl-1.0.2/lib/libcrypto.a

PROVER_OBJS = prover.c MPC_SHA256.c shared.c
VERIFIER_OBJS = verifier.c MPC_SHA256_VERIFIER.c shared.c

all: mpc_sha256_prover mpc_sha256_verifier

mpc_sha256_prover: $(PROVER_OBJS)
	$(CC) $(PROVER_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

mpc_sha256_verifier: $(VERIFIER_OBJS)
	$(CC) $(VERIFIER_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f mpc_sha256_prover mpc_sha256_verifier out*.bin