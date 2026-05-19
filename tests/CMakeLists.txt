# Tests live here
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

set(TEST_COMMON_LIBS
    mpc_hm_prover
    mpc_hm_verifier
    mpc_core
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

add_executable(hm_commit_test
    test_hm_commit.c
)
target_link_libraries(hm_commit_test
    ${TEST_COMMON_LIBS}
)

add_executable(mpc_sha256_test
    test_mpc_sha256.c
)
target_link_libraries(mpc_sha256_test
    ${TEST_COMMON_LIBS}
)

add_test(NAME hm_commit_test COMMAND hm_commit_test)
add_test(NAME mpc_sha256_test COMMAND mpc_sha256_test)
