cmake_minimum_required(VERSION 3.16)
project(HM_MPC C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options

add_compile_options(-march=native)

option(VERBOSE "Print debug messages" ON)
option(ENABLE_SANITIZERS "Enable ASan/UBSan" OFF)
option(HM_MPC_BUILD_TESTS "Build tests" OFF)

if(ENABLE_SANITIZERS)
  add_library(sanitizers INTERFACE)
  target_compile_options(sanitizers INTERFACE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -g
    -O1
  )
  target_link_options(sanitizers INTERFACE
    -fsanitize=address,undefined
  )
else()
  add_compile_options(-O3)
endif()


# Dependencies
find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)


# Internal implementation target.
# Tests can link against this target to access internal headers/functions.
add_library(hm_mpc_internal OBJECT
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mpc_sha256_prover.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mpc_sha256_verifier.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mpc_arithmetic.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mpc_universal_hash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mpc_halevi_micali.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/random_oracle.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/prg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/hm_buffer.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/thread_state.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/hm_impl.c
)
target_include_directories(hm_mpc_internal
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

### Enable debugging info
if(VERBOSE)
  target_compile_definitions(hm_mpc_internal PUBLIC VERBOSE)
endif()

### Enable address sanitizer
if(ENABLE_SANITIZERS)
  target_link_libraries(hm_mpc_internal PUBLIC sanitizers)
endif()

target_link_libraries(hm_mpc_internal
  PUBLIC
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

# Public library wrapper.
# External callers link this target and only get the public headers.
add_library(hm_mpc STATIC
  $<TARGET_OBJECTS:hm_mpc_internal>
)
target_include_directories(hm_mpc
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(hm_mpc
  PUBLIC
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

if(HM_MPC_BUILD_TESTS)
  include(FetchContent)

  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0
  )
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_subdirectory(tests)
endif()
