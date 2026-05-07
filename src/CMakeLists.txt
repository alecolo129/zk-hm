# =========================
# Include directories
# =========================
set(MPC_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_core)
set(MPC_SHA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_sha256)
set(MPC_INNER_PROD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc_inner_prod)

include_directories(
    ${MPC_CORE_DIR}
    ${MPC_SHA_DIR}
    ${MPC_INNER_PROD_DIR}
)

# =========================
# Libraries
# =========================

# SHA shared components
add_library(mpc_sha_core
    ${MPC_CORE_DIR}/shared.c
    ${MPC_CORE_DIR}/MPC_arithmetic.c
)

target_include_directories(mpc_sha_core
    PUBLIC ${MPC_CORE_DIR}
)

# Inner product
add_library(mpc_inner_prod
    ${MPC_INNER_PROD_DIR}/MPC_inner_prod.c
)

target_include_directories(mpc_inner_prod
    PUBLIC ${MPC_INNER_PROD_DIR}
)

# SHA256 prover-side
add_library(mpc_sha256
    ${MPC_SHA_DIR}/MPC_SHA256.c
)
target_include_directories(mpc_sha256
    PUBLIC ${MPC_SHA_DIR}
)

# SHA256 verifier-side
add_library(mpc_sha256_verifier
    ${MPC_SHA_DIR}/MPC_SHA256_VERIFIER.c
)

# =========================
# Executables
# =========================

add_executable(prover_mpc_sha256 prover.c)
target_link_libraries(prover_mpc_sha256
    mpc_sha256
    mpc_sha_core
    mpc_inner_prod
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

add_executable(verifier_mpc_sha256 verifier.c)
target_link_libraries(verifier_mpc_sha256
    mpc_sha256_verifier
    mpc_sha_core
    mpc_inner_prod
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

add_executable(prover_mpc_sha256_eq prover_message_eq.c)
target_link_libraries(prover_mpc_sha256_eq
    mpc_sha256
    mpc_sha_core
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

add_executable(verifier_mpc_sha256_eq verifier_eq.c)
target_link_libraries(verifier_mpc_sha256_eq
    mpc_sha256_verifier
    mpc_sha_core
    OpenMP::OpenMP_C
    OpenSSL::Crypto
)

# Output directory (optional)
set_target_properties(
    prover_mpc_sha256
    verifier_mpc_sha256
    # prover_mpc_sha256_eq
    # verifier_mpc_sha256_eq
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)