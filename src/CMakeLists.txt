
# =========================
# Include directories
# =========================
set(MPC_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_core)
set(MPC_SHA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_sha256)
set(MPC_UNIVERSAL_HASH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_universal_hash)

# =========================
# Libraries
# =========================

# Shared components
add_library(mpc_sha_core
    ${MPC_CORE_DIR}/shared.c
    ${MPC_CORE_DIR}/MPC_arithmetic.c
)
target_include_directories(mpc_sha_core PUBLIC ${MPC_CORE_DIR})
enable_sanitizers_for(mpc_sha_core)

# Inner product
add_library(mpc_universal_hash
    ${MPC_UNIVERSAL_HASH_DIR}/MPC_universal_hash.c
)
target_include_directories(mpc_universal_hash PUBLIC ${MPC_UNIVERSAL_HASH_DIR} ${MPC_CORE_DIR})
enable_sanitizers_for(mpc_universal_hash)

# Prover sha256
add_library(mpc_sha256
    ${MPC_SHA_DIR}/MPC_SHA256.c
)
target_include_directories(mpc_sha256 PUBLIC ${MPC_SHA_DIR} ${MPC_CORE_DIR})
enable_sanitizers_for(mpc_sha256)

# Verifier sha256
add_library(mpc_sha256_verifier
    ${MPC_SHA_DIR}/MPC_SHA256_VERIFIER.c
)
if(VERBOSE)
    target_compile_definitions(mpc_sha256_verifier PUBLIC VERBOSE)
endif()
target_include_directories(mpc_sha256_verifier PUBLIC ${MPC_SHA_DIR} ${MPC_CORE_DIR})
enable_sanitizers_for(mpc_sha256_verifier)

# =========================
# Executables
# =========================

add_executable(prover_mpc_sha256 prover.c)
target_link_libraries(prover_mpc_sha256 PRIVATE
    mpc_sha256
    mpc_sha_core
    mpc_universal_hash
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)
if(VERBOSE)
    target_compile_definitions(prover_mpc_sha256 PUBLIC VERBOSE)
endif()
enable_sanitizers_for(prover_mpc_sha256)

add_executable(verifier_mpc_sha256 verifier.c)
target_link_libraries(verifier_mpc_sha256 PRIVATE
    mpc_sha256_verifier
    mpc_sha_core
    mpc_universal_hash
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)
enable_sanitizers_for(verifier_mpc_sha256)

set_target_properties(
    prover_mpc_sha256
    verifier_mpc_sha256
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
