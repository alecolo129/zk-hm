set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks)

add_executable(hm_plain_benchmark benchmark_plain.cpp)
target_link_libraries(hm_plain_benchmark
  PRIVATE
    hm_mpc
    benchmark::benchmark
)
