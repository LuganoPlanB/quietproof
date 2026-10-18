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

add_executable(quietproof-cli src/quietproof_main.cc)
set_target_properties(quietproof-cli PROPERTIES OUTPUT_NAME quietproof)
target_link_libraries(quietproof-cli PRIVATE LongfellowZKQuietProof::quietproof)

install(TARGETS quietproof quietproof-cli EXPORT LongfellowZKQuietProofTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
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
  option(QUIETPROOF_ENABLE_POKC_SAGE_TEST
    "Run the Sage 10.6 reference model (requires Sage or Docker)" OFF)

  function(add_pokc_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE LongfellowZKQuietProof::quietproof)
    add_test(NAME ${target} COMMAND ${target} ${ARGN})
  endfunction()
  add_pokc_test(pokc-test tests/quietproof/pokc_test.cc)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test/results")
  set_tests_properties(pokc-test PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  add_pokc_test(compressed-key-sha256-test tests/quietproof/compressed_key_sha256_test.cc)
  add_pokc_test(key-ownership-test tests/quietproof/key_ownership_test.cc)
  add_pokc_test(ripemd160-test tests/quietproof/ripemd160_test.cc)
  add_pokc_test(quietproof-protocol-test tests/quietproof/protocol_test.cc)
  add_pokc_test(quietproof-challenge-test tests/quietproof/challenge_test.cc)
  add_pokc_test(quietproof-integration-test tests/quietproof/integration_test.cc)
  add_pokc_test(pokc-sage-test tests/quietproof/pokc_sage_vector_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/testdata/pokc_sage_vectors.json)
  add_test(NAME quietproof-cli-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/quietproof/cli_test.sh $<TARGET_FILE:quietproof-cli>)
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
