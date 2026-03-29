CC = gcc
CFLAGS = -O3 -fopenmp -I $(HOME)/openssl-1.0.2/include
LDFLAGS = $(HOME)/openssl-1.0.2/lib/libcrypto.a

PROVER_OBJS = prover.c MPC_SHA256.c shared.c
PROVER_EQ_OBJS = prover_message_eq.c MPC_SHA256.c shared.c

VERIFIER_OBJS = verifier.c MPC_SHA256_VERIFIER.c shared.c
# VERIFIER_MESSAGE_EQ_OBJS = verifier.c MPC_SHA256_VERIFIER.c shared.c

all: build_dir prover_mpc_sha256 verifier_mpc_sha256 prover_mpc_sha256_eq

build_dir:
	mkdir -p build

prover_mpc_sha256: $(PROVER_OBJS)
	$(CC) $(PROVER_OBJS) $(CFLAGS) $(LDFLAGS) -o build/$@

verifier_mpc_sha256: $(VERIFIER_OBJS)
	$(CC) $(VERIFIER_OBJS) $(CFLAGS) $(LDFLAGS) -o build/$@

prover_mpc_sha256_eq: $(PROVER_EQ_OBJS)
	$(CC) $(PROVER_EQ_OBJS) $(CFLAGS) $(LDFLAGS) -o build/$@

clean:
	rm -rf build out*.bin