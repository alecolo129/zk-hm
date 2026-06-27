set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)

add_executable(hm_bit_commit_c bit_commit.c)
target_link_libraries(hm_bit_commit_c PRIVATE hm_mpc)

add_executable(hm_bit_commit_cpp bit_commit.cpp)
target_link_libraries(hm_bit_commit_cpp PRIVATE hm_mpc)
