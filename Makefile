CC = gcc
CFLAGS = -O3 -fopenmp -I $(MPC_SHA_DIR) -I $(MPC_INNER_PROD_DIR) -I/usr/lib/gcc/x86_64-linux-gnu/13/include/
LDLIBS += -lcrypto


MPC_INNER_PROD_DIR = ./MPC_INNER_PROD
MPC_SHA_DIR = ./MPC_SHA256

INNER_PROD_TEST_OBJS = $(MPC_INNER_PROD_DIR)/test_hm_commit.c $(MPC_INNER_PROD_DIR)/MPC_inner_prod.c $(MPC_SHA_DIR)/shared.c

PROVER_OBJS = prover.c $(MPC_SHA_DIR)/MPC_SHA256.c $(MPC_SHA_DIR)/shared.c $(MPC_INNER_PROD_DIR)/MPC_inner_prod.c
PROVER_EQ_OBJS = prover_message_eq.c $(MPC_SHA_DIR)/MPC_SHA256.c $(MPC_SHA_DIR)/shared.c

VERIFIER_OBJS = verifier.c $(MPC_SHA_DIR)/MPC_SHA256_VERIFIER.c $(MPC_SHA_DIR)/shared.c $(MPC_INNER_PROD_DIR)/MPC_inner_prod.c
VERIFIER_EQ_OBJS = verifier_eq.c $(MPC_SHA_DIR)/MPC_SHA256_VERIFIER.c $(MPC_SHA_DIR)/shared.c

all: make_dirs build test

build: test prover_mpc_sha256 verifier_mpc_sha256 prover_mpc_sha256_eq verifier_mpc_sha256_eq


prover_mpc_sha256: $(PROVER_OBJS)
	$(CC) $(PROVER_OBJS) $(CFLAGS) -o build/$@ $(LDLIBS)

verifier_mpc_sha256: $(VERIFIER_OBJS)
	$(CC) $(VERIFIER_OBJS) $(CFLAGS) -o build/$@ $(LDLIBS)

prover_mpc_sha256_eq: $(PROVER_EQ_OBJS)
	$(CC) $(PROVER_EQ_OBJS) $(CFLAGS) -o build/$@ $(LDLIBS)

verifier_mpc_sha256_eq: $(VERIFIER_EQ_OBJS)
	$(CC) $(VERIFIER_EQ_OBJS) $(CFLAGS) -o build/$@ $(LDLIBS)

test: inner_prod_test

inner_prod_test:
	$(CC) $(INNER_PROD_TEST_OBJS) $(CFLAGS) -o test/$@ $(LDLIBS)

make_dirs:
	mkdir -p build test

clean:
	rm -rf build test out*.bin