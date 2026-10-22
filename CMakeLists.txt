cmake_minimum_required(VERSION 3.20)

project(LongfellowZKQuietProof VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

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

option(QUIETPROOF_BUILD_RPC "Build the native Bitcoin Core RPC library" ON)
if(QUIETPROOF_BUILD_RPC)
  find_package(CURL 7.62 REQUIRED)
  add_library(quietproof-rpc STATIC src/bitcoin_rpc.cc src/bitcoin_rpc_json.cc)
  add_library(LongfellowZKQuietProof::rpc ALIAS quietproof-rpc)
  set_target_properties(quietproof-rpc PROPERTIES
    EXPORT_NAME rpc POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(quietproof-rpc
    PUBLIC LongfellowZKQuietProof::quietproof PRIVATE CURL::libcurl)
  install(TARGETS quietproof-rpc EXPORT LongfellowZKQuietProofRpcTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(EXPORT LongfellowZKQuietProofRpcTargets
    FILE LongfellowZKQuietProofRpcTargets.cmake NAMESPACE LongfellowZKQuietProof::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LongfellowZKQuietProof)
endif()

option(QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST
  "Run isolated proof-heavy workflows against explicitly supplied Core 28 and 30" OFF)
if(QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST AND NOT QUIETPROOF_BUILD_RPC)
  message(FATAL_ERROR "Live regtest requires QUIETPROOF_BUILD_RPC")
endif()

find_package(Threads REQUIRED)
add_executable(quietproof-cli src/quietproof_main.cc)
set_target_properties(quietproof-cli PROPERTIES OUTPUT_NAME quietproof)
target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::quietproof Threads::Threads)
if(QUIETPROOF_BUILD_RPC)
  target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::rpc)
  target_compile_definitions(quietproof-cli PRIVATE QUIETPROOF_HAS_RPC=1)
endif()

install(TARGETS quietproof EXPORT LongfellowZKQuietProofTargets)
install(TARGETS quietproof-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/longfellow-zk-quietproof)
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
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof/docs)
install(DIRECTORY spec/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/LongfellowZKQuietProof/spec)

if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME quietproof-package-test
    COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/package_test.py
      --source ${CMAKE_CURRENT_SOURCE_DIR}
      --work ${CMAKE_CURRENT_BINARY_DIR}/package-test
      --prefix-path "${CMAKE_PREFIX_PATH}"
      --rpc-enabled "${QUIETPROOF_BUILD_RPC}"
      --generator "${CMAKE_GENERATOR}")
  option(QUIETPROOF_ENABLE_POKC_SAGE_TEST
    "Run the Sage 10.6 reference model (requires Sage or Docker)" OFF)

  function(add_pokc_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE LongfellowZKQuietProof::quietproof)
    add_test(NAME ${target} COMMAND ${target} ${ARGN})
  endfunction()
  if(QUIETPROOF_BUILD_RPC)
    add_executable(quietproof-rpc-test tests/quietproof/bitcoin_rpc_test.cc)
    target_include_directories(quietproof-rpc-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quietproof-rpc-test PRIVATE LongfellowZKQuietProof::rpc)
    add_test(NAME quietproof-rpc-test COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/rpc_http_fixture.py
      $<TARGET_FILE:quietproof-rpc-test>)
    set_tests_properties(quietproof-rpc-test PROPERTIES TIMEOUT 60)
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
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests/results")
  set_tests_properties(pokc-test PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    LABELS "proof-heavy" RUN_SERIAL TRUE TIMEOUT 1800)
  add_pokc_test(compressed-key-sha256-test tests/quietproof/compressed_key_sha256_test.cc)
  add_pokc_test(key-ownership-test tests/quietproof/key_ownership_test.cc)
  add_pokc_test(ripemd160-test tests/quietproof/ripemd160_test.cc)
  add_pokc_test(quietproof-protocol-test tests/quietproof/protocol_test.cc)
  add_pokc_test(quietproof-challenge-test tests/quietproof/challenge_test.cc)
  add_pokc_test(quietproof-integration-test tests/quietproof/integration_test.cc)
  add_pokc_test(pokc-sage-test tests/quietproof/pokc_sage_vector_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/testdata/pokc_sage_vectors.json)
  add_test(NAME quietproof-cli-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/cli_test.sh $<TARGET_FILE:quietproof-cli>)
  add_test(NAME quietproof-cli-context-test COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/cli_context_test.py $<TARGET_FILE:quietproof-cli>)
  set_tests_properties(quietproof-cli-context-test PROPERTIES TIMEOUT 180)
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
    set_tests_properties(quietproof-wallet-export-test PROPERTIES TIMEOUT 90)
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
  if(QUIETPROOF_ENABLE_POKC_SAGE_TEST)
    add_test(NAME pokc-sage-reference-test
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_pokc_sage.sh)
  endif()
endif()
