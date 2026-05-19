
# =========================
# Include directories
# =========================
set(MPC_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_core)
set(MPC_SHA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_sha256)
set(MPC_UNIVERSAL_HASH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_universal_hash)
set(UTILS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/utils)

# =========================
# Libraries
# =========================

### Shared components
add_library(mpc_core
    ${MPC_CORE_DIR}/shared.c
    ${MPC_CORE_DIR}/MPC_arithmetic.c
    ${MPC_UNIVERSAL_HASH_DIR}/MPC_universal_hash.c
    ${UTILS_DIR}/crypto.c
)
target_include_directories(mpc_core PUBLIC ${MPC_CORE_DIR} ${UTILS_DIR} ${MPC_UNIVERSAL_HASH_DIR})

### Prover
add_library(mpc_hm_prover
    ${MPC_SHA_DIR}/MPC_SHA256.c
)
target_include_directories(mpc_hm_prover PUBLIC ${MPC_CORE_DIR} ${MPC_SHA_DIR} ${UTILS_DIR} ${MPC_UNIVERSAL_HASH_DIR})

### Verifier
add_library(mpc_hm_verifier
    ${MPC_SHA_DIR}/MPC_SHA256_VERIFIER.c
)
target_include_directories(mpc_hm_verifier PUBLIC ${MPC_CORE_DIR} ${MPC_SHA_DIR} ${UTILS_DIR} ${MPC_UNIVERSAL_HASH_DIR})

# =========================
# Executables
# =========================

add_executable(hm_prover prover.c)
target_link_libraries(hm_prover PRIVATE
    mpc_hm_prover
    mpc_core
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

add_executable(hm_verifier verifier.c)
target_link_libraries(hm_verifier PRIVATE
    mpc_hm_verifier
    mpc_core
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

### Enable debugging info
if(VERBOSE)
    target_compile_definitions(mpc_core PUBLIC VERBOSE)
    target_compile_definitions(mpc_hm_prover PUBLIC VERBOSE)
    target_compile_definitions(mpc_hm_verifier PUBLIC VERBOSE)
    target_compile_definitions(hm_prover PUBLIC VERBOSE)
    target_compile_definitions(hm_verifier PUBLIC VERBOSE)
endif()

### Enable address sanitizer
if(ENABLE_SANITIZERS)
    target_link_libraries(mpc_core PUBLIC sanitizers)
    target_link_libraries(mpc_hm_prover PUBLIC sanitizers)
    target_link_libraries(mpc_hm_verifier PUBLIC sanitizers)
    target_link_libraries(hm_verifier PUBLIC sanitizers)
    target_link_libraries(hm_prover PUBLIC sanitizers)
endif()


set_target_properties(
    hm_prover
    hm_verifier
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
