cmake_minimum_required(VERSION 3.20)

set(QUIETPROOF_VERSION "0.1.0" CACHE STRING "QuietProof release version without the v prefix")
if(NOT QUIETPROOF_VERSION MATCHES "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")
  message(FATAL_ERROR "QUIETPROOF_VERSION must be a stable semantic version")
endif()
project(LongfellowZKQuietProof VERSION ${QUIETPROOF_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
set(_quietproof_native_default ON)
if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
  set(_quietproof_native_default OFF)
endif()
option(BUILD_TESTING "Build the native test suite" ${_quietproof_native_default})
include(CTest)
option(QUIETPROOF_BUILD_CLI "Build the native command-line application" ${_quietproof_native_default})
option(QUIETPROOF_BUILD_RPC "Build the native Bitcoin Core RPC library" ${_quietproof_native_default})
option(QUIETPROOF_BUILD_WASM "Build the WASI browser reactor" OFF)
option(QUIETPROOF_BUILD_GUI "Build the native Nuklear/SDL2 prover application" OFF)
option(QUIETPROOF_BUILD_SIGNATURE_MODE "Build and install the Bitcoin ECDSA constraint component" OFF)
if(QUIETPROOF_BUILD_GUI AND (NOT QUIETPROOF_BUILD_RPC OR CMAKE_SYSTEM_NAME STREQUAL "WASI"))
  message(FATAL_ERROR "QUIETPROOF_BUILD_GUI requires a native build with QUIETPROOF_BUILD_RPC=ON")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
  if(QUIETPROOF_BUILD_CLI OR QUIETPROOF_BUILD_RPC OR BUILD_TESTING)
    message(FATAL_ERROR "WASI requires QUIETPROOF_BUILD_CLI=OFF, QUIETPROOF_BUILD_RPC=OFF and BUILD_TESTING=OFF")
  endif()
elseif(QUIETPROOF_BUILD_WASM)
  message(FATAL_ERROR "QUIETPROOF_BUILD_WASM requires a wasm32 WASI toolchain")
endif()
if(BUILD_TESTING AND NOT QUIETPROOF_BUILD_CLI)
  message(FATAL_ERROR "The native test suite requires QUIETPROOF_BUILD_CLI=ON; use BUILD_TESTING=OFF for a library-only build")
endif()

set(LONGFELLOW_ZK_TARGET "LongfellowZK::static" CACHE STRING
    "Installed LongfellowZK target used by this project")
find_package(LongfellowZK CONFIG REQUIRED)
if(NOT TARGET ${LONGFELLOW_ZK_TARGET})
  message(FATAL_ERROR "LONGFELLOW_ZK_TARGET must name an installed LongfellowZK target")
endif()

add_library(quietproof INTERFACE)
add_library(LongfellowZKQuietProof::quietproof ALIAS quietproof)
target_compile_features(quietproof INTERFACE cxx_std_20)
target_include_directories(quietproof INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-quietproof>)
target_link_libraries(quietproof INTERFACE ${LONGFELLOW_ZK_TARGET})

if(QUIETPROOF_BUILD_SIGNATURE_MODE)
  # The reviewed relation uses complete formulas from the base SDK only.
  add_library(quietproof-signature INTERFACE)
  add_library(LongfellowZKQuietProof::signature ALIAS quietproof-signature)
  set_target_properties(quietproof-signature PROPERTIES EXPORT_NAME signature)
  target_link_libraries(quietproof-signature INTERFACE LongfellowZKQuietProof::quietproof)
  target_compile_definitions(quietproof-signature INTERFACE QUIETPROOF_HAS_SIGNATURE_MODE=1)
  install(TARGETS quietproof-signature EXPORT LongfellowZKQuietProofSignatureTargets)
  install(EXPORT LongfellowZKQuietProofSignatureTargets
    FILE LongfellowZKQuietProofSignatureTargets.cmake NAMESPACE LongfellowZKQuietProof::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
  install(FILES include/circuit/bitcoin_ecdsa.h include/circuit/bitcoin_ecdsa_witness.h
    include/circuit/signature_possession.h include/circuit/signature_possession_circuit.h
    include/circuit/signature_possession_witness.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-quietproof/circuit)
endif()

if(QUIETPROOF_BUILD_RPC)
  find_package(CURL 7.62 REQUIRED)
  add_library(quietproof-rpc STATIC src/bitcoin_rpc.cc src/bitcoin_rpc_json.cc)
  add_library(LongfellowZKQuietProof::rpc ALIAS quietproof-rpc)
  set_target_properties(quietproof-rpc PROPERTIES
    EXPORT_NAME rpc POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(quietproof-rpc
    PUBLIC LongfellowZKQuietProof::quietproof PRIVATE CURL::libcurl)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    # Implementation-only capability; rpc consumers do not implicitly select a
    # proof mode or acquire the signature circuit component.
    target_compile_definitions(quietproof-rpc PRIVATE QUIETPROOF_HAS_SIGNATURE_MODE=1)
  endif()
  install(TARGETS quietproof-rpc EXPORT LongfellowZKQuietProofRpcTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(EXPORT LongfellowZKQuietProofRpcTargets
    FILE LongfellowZKQuietProofRpcTargets.cmake NAMESPACE LongfellowZKQuietProof::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
endif()

option(QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST
  "Run isolated proof-heavy workflows against explicitly supplied Core 28 and 30" OFF)
option(QUIETPROOF_ENABLE_CORE32_SIGNING_TEST
  "Run the isolated stock Core 32.1 signing qualification (test-only oracle)" OFF)
if(QUIETPROOF_ENABLE_CORE32_SIGNING_TEST AND (NOT BUILD_TESTING OR CMAKE_SYSTEM_NAME STREQUAL "WASI"))
  message(FATAL_ERROR "Core 32 signing qualification requires native BUILD_TESTING=ON")
endif()
if(QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST AND NOT QUIETPROOF_BUILD_RPC)
  message(FATAL_ERROR "Live regtest requires QUIETPROOF_BUILD_RPC")
endif()

if(QUIETPROOF_BUILD_CLI)
  find_package(Threads REQUIRED)
  add_executable(quietproof-cli src/quietproof_main.cc)
  set_target_properties(quietproof-cli PROPERTIES OUTPUT_NAME quietproof)
  target_compile_definitions(quietproof-cli PRIVATE QUIETPROOF_VERSION="${PROJECT_VERSION}")
  target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::quietproof Threads::Threads)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::signature)
  endif()
  if(QUIETPROOF_BUILD_RPC)
    target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::rpc)
    target_compile_definitions(quietproof-cli PRIVATE QUIETPROOF_HAS_RPC=1)
  endif()
  install(TARGETS quietproof-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(QUIETPROOF_BUILD_GUI)
  add_subdirectory(src/gui)
endif()

if(QUIETPROOF_BUILD_WASM)
  add_executable(quietproof-wasm src/wasm/reactor.cc)
  target_link_libraries(quietproof-wasm PRIVATE LongfellowZKQuietProof::quietproof)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    target_link_libraries(quietproof-wasm PRIVATE LongfellowZKQuietProof::signature)
  endif()
  target_link_options(quietproof-wasm PRIVATE
    -mexec-model=reactor
    -Wl,--initial-memory=16777216 -Wl,--max-memory=2147483648
    -Wl,-z,stack-size=1048576
    -Wl,--export=quietproof_wasm_abi_version
    -Wl,--export=quietproof_wasm_capabilities
    -Wl,--export=quietproof_wasm_alloc -Wl,--export=quietproof_wasm_free
    -Wl,--export=quietproof_wasm_smoke
    -Wl,--export=quietproof_wasm_create_request -Wl,--export=quietproof_wasm_inspect
    -Wl,--export=quietproof_wasm_result_data -Wl,--export=quietproof_wasm_result_size
    -Wl,--export=quietproof_wasm_error_data -Wl,--export=quietproof_wasm_error_size
    -Wl,--export=quietproof_wasm_prepare -Wl,--export=quietproof_wasm_verify
    -Wl,--export=quietproof_wasm_evaluate -Wl,--export=quietproof_wasm_reset)
  set_target_properties(quietproof-wasm PROPERTIES OUTPUT_NAME quietproof SUFFIX ".wasm")
  install(TARGETS quietproof-wasm RUNTIME DESTINATION ${CMAKE_INSTALL_DATADIR}/quietproof/wasm)
endif()

install(TARGETS quietproof EXPORT LongfellowZKQuietProofTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-quietproof
  PATTERN "bitcoin_ecdsa.h" EXCLUDE
  PATTERN "bitcoin_ecdsa_witness.h" EXCLUDE
  PATTERN "signature_possession*.h" EXCLUDE)
install(EXPORT LongfellowZKQuietProofTargets
  FILE LongfellowZKQuietProofTargets.cmake NAMESPACE LongfellowZKQuietProof::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
configure_package_config_file(cmake/LongfellowZKQuietProofConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKQuietProofConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKQuietProofConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKQuietProofConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/LongfellowZKQuietProofConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
install(FILES README.md pokc.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof)
install(DIRECTORY docs/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof/docs
  PATTERN ".vitepress/dist" EXCLUDE
  PATTERN ".vitepress/cache" EXCLUDE)
install(DIRECTORY spec/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof/spec)
# Public reference symlinks in docs/public/references retain their repository
# relative layout in installed documentation.
install(FILES scripts/generate_signature_profile.py
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof/scripts)

if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME quietproof-signature-vectors-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_signature_vectors.py
    --check ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-vectors.json)
  add_test(NAME quietproof-signature-reference-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_vectors_test.py)
  set_tests_properties(quietproof-signature-vectors-test quietproof-signature-reference-test
    PROPERTIES TIMEOUT 30 LABELS "signature-reference")
  if(QUIETPROOF_ENABLE_CORE32_SIGNING_TEST)
    set(QUIETPROOF_CORE32_DIR "" CACHE PATH "Directory containing verified stock Core 32.1 bitcoind and bitcoin-cli")
    foreach(program IN ITEMS bitcoind bitcoin-cli)
      if(NOT EXISTS "${QUIETPROOF_CORE32_DIR}/${program}")
        message(FATAL_ERROR "Signing regtest requires QUIETPROOF_CORE32_DIR containing ${program}")
      endif()
    endforeach()
    # Deliberately confined to test executables, never exported or installed.
    # Core 32.1's verified source bundles this exact public API version.
    find_package(libsecp256k1 0.8.1 EXACT CONFIG REQUIRED)
    add_executable(quietproof-signing-oracle tests/signing_oracle.cc)
    target_compile_features(quietproof-signing-oracle PRIVATE cxx_std_20)
    target_link_libraries(quietproof-signing-oracle PRIVATE libsecp256k1::secp256k1)
    add_test(NAME quietproof-signing-oracle-test COMMAND quietproof-signing-oracle --self-test)
    add_test(NAME quietproof-signature-oracle-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_signature_vectors.py
      --check ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-vectors.json
      --oracle $<TARGET_FILE:quietproof-signing-oracle>)
    set_tests_properties(quietproof-signature-oracle-test PROPERTIES TIMEOUT 60 LABELS "signature-reference")
    add_test(NAME quietproof-signing-regtest-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/bitcoin_core_signing_regtest.py
      --core32 "${QUIETPROOF_CORE32_DIR}" --oracle $<TARGET_FILE:quietproof-signing-oracle>)
    set_tests_properties(quietproof-signing-oracle-test PROPERTIES TIMEOUT 10 LABELS "signature-reference")
    set_tests_properties(quietproof-signing-regtest-test PROPERTIES
      TIMEOUT 300 RUN_SERIAL TRUE LABELS "bitcoin-core32;signature-reference")
  endif()
  add_test(NAME quietproof-package-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/package_test.py
      --source ${CMAKE_CURRENT_SOURCE_DIR}
      --work ${CMAKE_CURRENT_BINARY_DIR}/package-test
      --prefix-path "${CMAKE_PREFIX_PATH}"
      --rpc-enabled "${QUIETPROOF_BUILD_RPC}"
      --signature-enabled "${QUIETPROOF_BUILD_SIGNATURE_MODE}"
      --generator "${CMAKE_GENERATOR}")
  option(QUIETPROOF_ENABLE_POKC_SAGE_TEST
    "Run the Sage 10.6 reference model (requires Sage or Docker)" OFF)
  option(QUIETPROOF_ENABLE_POSC_SAGE_TEST
    "Run the PoSC Sage 10.6 reference model (requires Sage or Docker)" OFF)

  function(add_pokc_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE LongfellowZKQuietProof::quietproof)
    add_test(NAME ${target} COMMAND ${target} ${ARGN})
  endfunction()
  add_executable(quietproof-signature-acceptance-test tests/quietproof/nonce_acceptance_test.cc)
  target_link_libraries(quietproof-signature-acceptance-test PRIVATE LongfellowZKQuietProof::quietproof)
  add_test(NAME quietproof-signature-acceptance-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/nonce_acceptance_test.py
    --driver $<TARGET_FILE:quietproof-signature-acceptance-test>)
  set_tests_properties(quietproof-signature-acceptance-test PROPERTIES TIMEOUT 60)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    # Explicit, proof-heavy measurement tool; never part of the default build/test run.
    add_executable(quietproof-relation-benchmark EXCLUDE_FROM_ALL tests/quietproof/relation_benchmark.cc)
    target_link_libraries(quietproof-relation-benchmark PRIVATE LongfellowZKQuietProof::signature)
    add_executable(quietproof-signature-verifier-test tests/quietproof/signature_verifier_test.cc)
    target_link_libraries(quietproof-signature-verifier-test PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-verifier-test COMMAND quietproof-signature-verifier-test
      ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
    add_executable(quietproof-signature-proof-test tests/quietproof/signature_proof_test.cc)
    target_link_libraries(quietproof-signature-proof-test PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-proof-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_proof_test.py
      --driver $<TARGET_FILE:quietproof-signature-proof-test> --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results)
    set_tests_properties(quietproof-signature-proof-test
      PROPERTIES TIMEOUT 7200 RUN_SERIAL TRUE LABELS "signature-reference;proof-heavy")
    add_executable(quietproof-signature-identity-test tests/quietproof/signature_identity_test.cc)
    target_link_libraries(quietproof-signature-identity-test PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-identity-test COMMAND quietproof-signature-identity-test)
    add_executable(quietproof-ecdsa-circuit-test tests/quietproof/signature_possession_test.cc)
    target_link_libraries(quietproof-ecdsa-circuit-test PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-ecdsa-circuit-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_possession_test.py
      --circuit $<TARGET_FILE:quietproof-ecdsa-circuit-test>)
    set_tests_properties(quietproof-ecdsa-circuit-test
      PROPERTIES TIMEOUT 1800 RUN_SERIAL TRUE LABELS "signature-reference")
    add_test(NAME quietproof-posc-sage-vector-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/posc_sage_vector_test.py
      --circuit $<TARGET_FILE:quietproof-ecdsa-circuit-test>)
    set_tests_properties(quietproof-posc-sage-vector-test
      PROPERTIES TIMEOUT 660 RUN_SERIAL TRUE LABELS "signature-reference")
    add_executable(quietproof-ecdsa-prototype tests/quietproof/bitcoin_ecdsa_test.cc)
    target_link_libraries(quietproof-ecdsa-prototype PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-ecdsa-constraint-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/bitcoin_ecdsa_corpus_test.py
      --prototype $<TARGET_FILE:quietproof-ecdsa-prototype>)
    add_test(NAME quietproof-ecdsa-advice-test COMMAND quietproof-ecdsa-prototype --mutations)
    set_tests_properties(quietproof-ecdsa-constraint-test quietproof-ecdsa-advice-test
      PROPERTIES TIMEOUT 180 LABELS "signature-reference")
    add_test(NAME quietproof-ecdsa-prototype-proof-test COMMAND quietproof-ecdsa-prototype
      --proof ${CMAKE_CURRENT_BINARY_DIR}/tests/results/ecdsa-prototype.proof)
    set_tests_properties(quietproof-ecdsa-prototype-proof-test
      PROPERTIES TIMEOUT 1800 RUN_SERIAL TRUE LABELS "signature-reference;proof-heavy")
  endif()
  if(QUIETPROOF_BUILD_RPC)
    add_executable(quietproof-signature-state-rpc-test tests/quietproof/signature_state_rpc_test.cc)
    target_include_directories(quietproof-signature-state-rpc-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quietproof-signature-state-rpc-test PRIVATE LongfellowZKQuietProof::rpc)
    add_test(NAME quietproof-signature-state-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_state_rpc_test.py
      --driver $<TARGET_FILE:quietproof-signature-state-rpc-test>)
    set_tests_properties(quietproof-signature-state-rpc-test PROPERTIES TIMEOUT 30)
    if(QUIETPROOF_ENABLE_CORE32_SIGNING_TEST)
      add_test(NAME quietproof-signature-state-core-test COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_state_rpc_test.py
        --driver $<TARGET_FILE:quietproof-signature-state-rpc-test>
        --core32 "${QUIETPROOF_CORE32_DIR}" --oracle $<TARGET_FILE:quietproof-signing-oracle>)
      set_tests_properties(quietproof-signature-state-core-test PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE LABELS "bitcoin-core32")
    endif()
    add_executable(quietproof-rpc-test tests/quietproof/bitcoin_rpc_test.cc)
    target_include_directories(quietproof-rpc-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quietproof-rpc-test PRIVATE LongfellowZKQuietProof::rpc)
    add_test(NAME quietproof-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/rpc_http_fixture.py
      $<TARGET_FILE:quietproof-rpc-test>)
    set_tests_properties(quietproof-rpc-test PROPERTIES TIMEOUT 60)
    add_executable(quietproof-signature-rpc-driver tests/quietproof/signature_rpc_driver.cc)
    target_link_libraries(quietproof-signature-rpc-driver PRIVATE LongfellowZKQuietProof::rpc)
    set(_signature_rpc_disabled)
    if(NOT QUIETPROOF_BUILD_SIGNATURE_MODE)
      set(_signature_rpc_disabled --disabled)
    endif()
    add_test(NAME quietproof-signature-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_rpc_test.py
      --driver $<TARGET_FILE:quietproof-signature-rpc-driver> ${_signature_rpc_disabled})
    set_tests_properties(quietproof-signature-rpc-test PROPERTIES TIMEOUT 120)
    if(QUIETPROOF_BUILD_SIGNATURE_MODE AND QUIETPROOF_ENABLE_CORE32_SIGNING_TEST)
      add_test(NAME quietproof-signature-rpc-core-test COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_rpc_test.py
        --driver $<TARGET_FILE:quietproof-signature-rpc-driver>
        --core32 "${QUIETPROOF_CORE32_DIR}" --oracle $<TARGET_FILE:quietproof-signing-oracle>)
      set_tests_properties(quietproof-signature-rpc-core-test PROPERTIES
        TIMEOUT 180 RUN_SERIAL TRUE LABELS "bitcoin-core32;signature-reference")
    endif()
  endif()
  if(QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST)
    set(QUIETPROOF_CORE28_DIR "" CACHE PATH "Directory containing Core 28 bitcoind and bitcoin-cli")
    set(QUIETPROOF_CORE30_DIR "" CACHE PATH "Directory containing Core 30 bitcoind and bitcoin-cli")
    foreach(version IN ITEMS 28 30)
      foreach(program IN ITEMS bitcoind bitcoin-cli)
        if(NOT EXISTS "${QUIETPROOF_CORE${version}_DIR}/${program}")
          message(FATAL_ERROR "Regtest requires QUIETPROOF_CORE${version}_DIR containing ${program}")
        endif()
      endforeach()
    endforeach()
    add_executable(quietproof-rpc-api-driver tests/quietproof/rpc_api_driver.cc)
    target_link_libraries(quietproof-rpc-api-driver PRIVATE LongfellowZKQuietProof::rpc)
    add_executable(quietproof-regtest-driver tests/quietproof/regtest_rpc_test.cc)
    target_link_libraries(quietproof-regtest-driver PRIVATE LongfellowZKQuietProof::rpc)
    add_test(NAME quietproof-regtest-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/regtest_rpc_test.py
      --core28 "${QUIETPROOF_CORE28_DIR}" --core30 "${QUIETPROOF_CORE30_DIR}"
      --cli $<TARGET_FILE:quietproof-cli>
      --api-driver $<TARGET_FILE:quietproof-rpc-api-driver>
      --driver $<TARGET_FILE:quietproof-regtest-driver>)
    set_tests_properties(quietproof-regtest-rpc-test PROPERTIES
      LABELS "bitcoin-regtest;proof-heavy" RUN_SERIAL TRUE TIMEOUT 14400)
  else()
    add_test(NAME quietproof-regtest-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/regtest_rpc_test.py --not-enabled)
    set_tests_properties(quietproof-regtest-rpc-test PROPERTIES
      LABELS "bitcoin-regtest;proof-heavy" SKIP_RETURN_CODE 77)
  endif()
  add_pokc_test(pokc-test tests/quietproof/pokc_test.cc)
  add_test(NAME pokc-timestamp-test COMMAND pokc-test --timestamp-roundtrip)
  set_tests_properties(pokc-timestamp-test PROPERTIES
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 600)
  add_pokc_test(p2sh-multisig-test tests/quietproof/p2sh_multisig_test.cc)
  add_test(NAME p2sh-multisig-proof-test COMMAND p2sh-multisig-test --proofs)
  set_tests_properties(p2sh-multisig-proof-test PROPERTIES
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 1800)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests/results")
  set_tests_properties(pokc-test PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 1800)
  add_pokc_test(compressed-key-sha256-test tests/quietproof/compressed_key_sha256_test.cc)
  add_pokc_test(key-ownership-test tests/quietproof/key_ownership_test.cc)
  add_pokc_test(ripemd160-test tests/quietproof/ripemd160_test.cc)
  add_pokc_test(quietproof-protocol-test tests/quietproof/protocol_test.cc)
  add_pokc_test(quietproof-signature-statement-disabled-test tests/quietproof/signature_statement_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
  add_executable(quietproof-signature-proof-disabled-test tests/quietproof/signature_proof_test.cc)
  add_pokc_test(quietproof-signature-verifier-disabled-test tests/quietproof/signature_verifier_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
  target_link_libraries(quietproof-signature-proof-disabled-test PRIVATE LongfellowZKQuietProof::quietproof)
  add_test(NAME quietproof-signature-proof-disabled-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_proof_test.py
    --driver $<TARGET_FILE:quietproof-signature-proof-disabled-test>
    --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results --disabled)
  set_tests_properties(quietproof-signature-proof-disabled-test PROPERTIES TIMEOUT 30)
  add_pokc_test(quietproof-signature-codec-disabled-test tests/quietproof/signature_codec_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
  add_pokc_test(quietproof-signature-envelope-disabled-test tests/quietproof/signature_envelope_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
  add_executable(quietproof-signature-receipt-disabled-driver tests/quietproof/signature_receipt_driver.cc)
  target_link_libraries(quietproof-signature-receipt-disabled-driver PRIVATE LongfellowZKQuietProof::quietproof)
  add_test(NAME quietproof-signature-receipt-disabled-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_receipt_test.py
    --driver $<TARGET_FILE:quietproof-signature-receipt-disabled-driver> --disabled
    --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results)
  set_tests_properties(quietproof-signature-receipt-disabled-test PROPERTIES TIMEOUT 120)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    add_pokc_test(quietproof-signature-envelope-test tests/quietproof/signature_envelope_test.cc
      ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
    target_link_libraries(quietproof-signature-envelope-test PRIVATE LongfellowZKQuietProof::signature)
    add_executable(quietproof-signature-receipt-driver tests/quietproof/signature_receipt_driver.cc)
    target_link_libraries(quietproof-signature-receipt-driver PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-receipt-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_receipt_test.py
      --driver $<TARGET_FILE:quietproof-signature-receipt-driver> --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results)
    set_tests_properties(quietproof-signature-receipt-test PROPERTIES TIMEOUT 120)
    if(QUIETPROOF_ENABLE_CORE32_SIGNING_TEST)
      add_test(NAME quietproof-signature-receipt-core-test COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_receipt_test.py
        --driver $<TARGET_FILE:quietproof-signature-receipt-driver> --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results
        --core32 ${QUIETPROOF_CORE32_DIR} --oracle $<TARGET_FILE:quietproof-signing-oracle>)
      set_tests_properties(quietproof-signature-receipt-core-test PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE LABELS "bitcoin-core32;signature-reference")
    endif()
    add_pokc_test(quietproof-signature-statement-test tests/quietproof/signature_statement_test.cc
      ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
    target_link_libraries(quietproof-signature-statement-test PRIVATE LongfellowZKQuietProof::signature)
    add_pokc_test(quietproof-signature-codec-test tests/quietproof/signature_codec_test.cc
      ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
    target_link_libraries(quietproof-signature-codec-test PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-codec-reference-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_codec_reference_test.py
      --codec $<TARGET_FILE:quietproof-signature-codec-test>
      --fixture ${CMAKE_CURRENT_SOURCE_DIR}/spec/signature-profile-v1.json)
    set_tests_properties(quietproof-signature-codec-reference-test PROPERTIES TIMEOUT 60 LABELS "signature-reference")
    # Compile base-only and enabled objects separately, then link in both
    # orders. Force unoptimized/no-inline coverage even in Release builds.
    foreach(variant IN ITEMS debug optimized)
      foreach(capability IN ITEMS disabled enabled)
        set(object quietproof-signature-capability-${variant}-${capability})
        add_library(${object} OBJECT tests/quietproof/signature_capability/${capability}.cc)
        if(capability STREQUAL "enabled")
          target_link_libraries(${object} PRIVATE LongfellowZKQuietProof::signature)
        else()
          target_link_libraries(${object} PRIVATE LongfellowZKQuietProof::quietproof)
        endif()
        set_property(TARGET ${object} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
          target_compile_options(${object} PRIVATE -fno-lto)
          if(variant STREQUAL "debug")
            target_compile_options(${object} PRIVATE -O0 -fno-inline -fno-inline-functions)
          else()
            target_compile_options(${object} PRIVATE -O2)
          endif()
        elseif(MSVC)
          if(variant STREQUAL "debug")
            target_compile_options(${object} PRIVATE /Od /Ob0)
          else()
            target_compile_options(${object} PRIVATE /O2)
          endif()
        endif()
      endforeach()
      foreach(first IN ITEMS disabled enabled)
        if(first STREQUAL "disabled")
          set(second enabled)
        else()
          set(second disabled)
        endif()
        set(test quietproof-signature-capability-${variant}-${first}-first-test)
        add_executable(${test} tests/quietproof/signature_capability/main.cc
          $<TARGET_OBJECTS:quietproof-signature-capability-${variant}-${first}>
          $<TARGET_OBJECTS:quietproof-signature-capability-${variant}-${second}>)
        target_link_libraries(${test} PRIVATE LongfellowZKQuietProof::quietproof)
        add_test(NAME ${test} COMMAND ${test})
      endforeach()
    endforeach()
  endif()
  add_pokc_test(quietproof-challenge-test tests/quietproof/challenge_test.cc)
  add_pokc_test(quietproof-browser-codec-test tests/wasm/codec_test.cc)
  add_pokc_test(quietproof-browser-verifier-test tests/wasm/verifier_test.cc
    ${CMAKE_CURRENT_BINARY_DIR}/tests/wasm-real)
  set_tests_properties(quietproof-browser-verifier-test PROPERTIES
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 600)
  # Explicit fixture generator: public disposable scalars; never part of WASM.
  add_executable(quietproof-browser-fixtures tests/wasm/proof_fixtures.cc)
  target_link_libraries(quietproof-browser-fixtures PRIVATE LongfellowZKQuietProof::quietproof)
  add_executable(quietproof-browser-signature-test tests/wasm/signature_verifier_test.cc)
  target_link_libraries(quietproof-browser-signature-test PRIVATE LongfellowZKQuietProof::quietproof)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    target_link_libraries(quietproof-browser-signature-test PRIVATE LongfellowZKQuietProof::signature)
    set(_qp_browser_disabled)
  else()
    set(_qp_browser_disabled --disabled)
  endif()
  add_test(NAME quietproof-browser-signature-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/wasm/signature_fixtures.py
    --driver $<TARGET_FILE:quietproof-browser-signature-test>
    --output ${CMAKE_CURRENT_BINARY_DIR}/tests/wasm-real ${_qp_browser_disabled})
  set_tests_properties(quietproof-browser-signature-test PROPERTIES
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 7200)
  add_executable(quietproof-browser-context-linkage-test
    tests/wasm/context_linkage/main.cc tests/wasm/context_linkage/disabled.cc)
  target_link_libraries(quietproof-browser-context-linkage-test PRIVATE LongfellowZKQuietProof::quietproof)
  add_test(NAME quietproof-browser-context-linkage-test COMMAND quietproof-browser-context-linkage-test)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    foreach(variant IN ITEMS debug optimized)
      foreach(capability IN ITEMS disabled enabled)
        set(object quietproof-browser-context-${variant}-${capability})
        add_library(${object} OBJECT tests/wasm/context_linkage/${capability}.cc)
        if(capability STREQUAL "enabled")
          target_link_libraries(${object} PRIVATE LongfellowZKQuietProof::signature)
        else()
          target_link_libraries(${object} PRIVATE LongfellowZKQuietProof::quietproof)
        endif()
        set_property(TARGET ${object} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
          target_compile_options(${object} PRIVATE -fno-lto)
          if(variant STREQUAL "debug")
            target_compile_options(${object} PRIVATE -O0 -fno-inline -fno-inline-functions)
          else()
            target_compile_options(${object} PRIVATE -O2)
          endif()
        elseif(MSVC)
          if(variant STREQUAL "debug")
            target_compile_options(${object} PRIVATE /Od /Ob0)
          else()
            target_compile_options(${object} PRIVATE /O2)
          endif()
        endif()
      endforeach()
      foreach(first IN ITEMS disabled enabled)
        if(first STREQUAL "disabled")
          set(second enabled)
        else()
          set(second disabled)
        endif()
        set(test quietproof-browser-context-${variant}-${first}-first-test)
        add_executable(${test} tests/wasm/context_linkage/main.cc
          $<TARGET_OBJECTS:quietproof-browser-context-${variant}-${first}>
          $<TARGET_OBJECTS:quietproof-browser-context-${variant}-${second}>)
        target_compile_definitions(${test} PRIVATE QUIETPROOF_TEST_BROWSER_MIXED=1)
        target_link_libraries(${test} PRIVATE LongfellowZKQuietProof::quietproof)
        add_test(NAME ${test} COMMAND ${test})
      endforeach()
    endforeach()
    add_test(NAME quietproof-browser-context-proof-test
      COMMAND quietproof-browser-context-optimized-disabled-first-test ${CMAKE_CURRENT_BINARY_DIR}/tests/wasm-real)
    set_tests_properties(quietproof-browser-context-proof-test PROPERTIES
      DEPENDS quietproof-browser-signature-test LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 600)
  endif()
  add_pokc_test(quietproof-integration-test tests/quietproof/integration_test.cc)
  add_pokc_test(pokc-sage-test tests/quietproof/pokc_sage_vector_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/testdata/pokc_sage_vectors.json)
  add_test(NAME quietproof-cli-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/cli_test.sh $<TARGET_FILE:quietproof-cli>)
  add_test(NAME quietproof-cli-context-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/cli_context_test.py $<TARGET_FILE:quietproof-cli>
    --rpc-enabled ${QUIETPROOF_BUILD_RPC})
  set_tests_properties(quietproof-cli-context-test PROPERTIES TIMEOUT 180)
  set(_signature_cli_capability)
  if(NOT QUIETPROOF_BUILD_SIGNATURE_MODE)
    set(_signature_cli_capability --disabled)
  endif()
  set(_signature_cli_fault)
  option(QUIETPROOF_ENABLE_CLI_PRELOAD_TEST "Test CLI file faults using a Linux dynamic-loader helper" ON)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND QUIETPROOF_ENABLE_CLI_PRELOAD_TEST)
    add_library(quietproof-signature-cli-fault SHARED tests/quietproof/signature_cli_fault.cc)
    target_link_libraries(quietproof-signature-cli-fault PRIVATE ${CMAKE_DL_LIBS})
    set(_signature_cli_fault --fault $<TARGET_FILE:quietproof-signature-cli-fault>)
  endif()
  add_test(NAME quietproof-signature-cli-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_cli_test.py
    --cli $<TARGET_FILE:quietproof-cli> --rpc ${QUIETPROOF_BUILD_RPC}
    ${_signature_cli_capability} ${_signature_cli_fault})
  set_tests_properties(quietproof-signature-cli-test PROPERTIES TIMEOUT 120)
  if(QUIETPROOF_BUILD_SIGNATURE_MODE)
    add_executable(quietproof-signature-cli-verify tests/quietproof/signature_cli_verify.cc)
    target_link_libraries(quietproof-signature-cli-verify PRIVATE LongfellowZKQuietProof::signature)
    add_test(NAME quietproof-signature-cli-proof-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_cli_test.py
      --cli $<TARGET_FILE:quietproof-cli> --rpc ${QUIETPROOF_BUILD_RPC}
      --proof-verifier $<TARGET_FILE:quietproof-signature-cli-verify>)
    set_tests_properties(quietproof-signature-cli-proof-test PROPERTIES
      TIMEOUT 3600 RUN_SERIAL TRUE LABELS "proof-heavy")
    if(QUIETPROOF_BUILD_RPC AND QUIETPROOF_ENABLE_CORE32_SIGNING_TEST)
      add_test(NAME quietproof-signature-cli-core-test COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_cli_test.py
        --cli $<TARGET_FILE:quietproof-cli> --rpc ON
        --proof-verifier $<TARGET_FILE:quietproof-signature-cli-verify>
        --core32 "${QUIETPROOF_CORE32_DIR}" --oracle $<TARGET_FILE:quietproof-signing-oracle>)
      set_tests_properties(quietproof-signature-cli-core-test PROPERTIES
        TIMEOUT 3600 RUN_SERIAL TRUE LABELS "bitcoin-core32;proof-heavy")
      add_test(NAME quietproof-signature-funds-regtest-test COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/signature_funds_regtest.py
        --cli $<TARGET_FILE:quietproof-cli> --core32 "${QUIETPROOF_CORE32_DIR}"
        --oracle $<TARGET_FILE:quietproof-signing-oracle>
        --source ${CMAKE_CURRENT_SOURCE_DIR} --prefix-path "${CMAKE_PREFIX_PATH}"
        --work ${CMAKE_CURRENT_BINARY_DIR}/tests/results)
      set_tests_properties(quietproof-signature-funds-regtest-test PROPERTIES
        TIMEOUT 7200 RUN_SERIAL TRUE LABELS "bitcoin-core32;proof-heavy;signature-end-to-end")
    endif()
  endif()
  if(QUIETPROOF_BUILD_RPC)
    set(_quietproof_cli_rpc_mode --cli)
  else()
    set(_quietproof_cli_rpc_mode --cli-off)
  endif()
  add_test(NAME quietproof-cli-rpc-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/rpc_http_fixture.py
    $<TARGET_FILE:quietproof-cli> ${_quietproof_cli_rpc_mode})
  set_tests_properties(quietproof-cli-rpc-test PROPERTIES TIMEOUT 60)
  if(QUIETPROOF_BUILD_RPC)
    add_test(NAME quietproof-wallet-export-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/wallet_export_test.py $<TARGET_FILE:quietproof-cli>)
    set_tests_properties(quietproof-wallet-export-test PROPERTIES
      TIMEOUT 300 LABELS "proof-heavy" RUN_SERIAL TRUE)
  endif()
  add_test(NAME quietproof-prove-feedback-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/prove_feedback_test.py $<TARGET_FILE:quietproof-cli>)
  add_executable(quietproof-progress-test tests/quietproof/proof_progress_test.cc)
  target_compile_features(quietproof-progress-test PRIVATE cxx_std_20)
  target_include_directories(quietproof-progress-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(quietproof-progress-test PRIVATE Threads::Threads)
  add_test(NAME quietproof-progress-test COMMAND quietproof-progress-test)
  set_tests_properties(quietproof-progress-test PROPERTIES TIMEOUT 10)
  add_test(NAME pokc-vector-generation-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/pokc_vector_generation_test.py)
  add_test(NAME quietproof-spec-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_quietproof_spec.py)
  add_test(NAME quietproof-naming-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/naming_test.py)
  add_test(NAME posc-reference-contract-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/posc_reference_contract_test.py)
  if(QUIETPROOF_ENABLE_POKC_SAGE_TEST)
    add_test(NAME pokc-sage-reference-test
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_pokc_sage.sh)
  endif()
  if(QUIETPROOF_ENABLE_POSC_SAGE_TEST)
    add_test(NAME posc-sage-reference-test
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_posc_sage.py)
    set_tests_properties(posc-sage-reference-test PROPERTIES TIMEOUT 600 LABELS "signature-reference")
  endif()
endif()
