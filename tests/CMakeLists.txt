# Tests live here
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(hm_commit_test
    test_hm_plain.cpp
    test_hm_zk.cpp
)
target_link_libraries(hm_commit_test PRIVATE hm_mpc GTest::gtest_main)
add_test(NAME hm_commit_test COMMAND hm_commit_test)

add_executable(hm_primitives_test
    test_mpc_sha256.cpp
    test_mpc_universal_hash.cpp
    test_toeplitz.cpp
)
target_link_libraries(hm_primitives_test PRIVATE hm_mpc_internal GTest::gtest_main)
add_test(NAME hm_primitives_test COMMAND hm_primitives_test)
