find_package(SDL2 2.0.22 CONFIG REQUIRED)

add_library(quietproof-gui-request STATIC request.cc request_review.cc)
target_compile_features(quietproof-gui-request PUBLIC cxx_std_20)
target_link_libraries(quietproof-gui-request PUBLIC LongfellowZKQuietProof::quietproof)
target_include_directories(quietproof-gui-request PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(quietproof-gui-request PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)

find_package(Threads REQUIRED)
add_library(quietproof-gui-node STATIC node_settings.cc node_probe.cc preferences.cc)
target_compile_features(quietproof-gui-node PUBLIC cxx_std_20)
target_link_libraries(quietproof-gui-node PUBLIC LongfellowZKQuietProof::rpc Threads::Threads)
target_include_directories(quietproof-gui-node PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(quietproof-gui-node PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)

add_executable(quietproof-prover-gui main.cc application.cc theme.cc shell.cc nuklear_backend.cc)
set_target_properties(quietproof-prover-gui PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
target_compile_features(quietproof-prover-gui PRIVATE cxx_std_20)
target_link_libraries(quietproof-prover-gui PRIVATE
  quietproof-gui-node quietproof-gui-request SDL2::SDL2)
target_compile_definitions(quietproof-prover-gui PRIVATE SDL_MAIN_HANDLED)
target_compile_options(quietproof-prover-gui PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)

# Locate assets beside the build executable, or relative to the installed one.
# Keep development-tree paths out of the application binary.
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/quietproof-gui-assets")
configure_file(assets/Inter.ttf
  "${PROJECT_BINARY_DIR}/quietproof-gui-assets/Inter.ttf" COPYONLY)
file(RELATIVE_PATH QUIETPROOF_GUI_ASSET_PATH
  "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_DATADIR}/quietproof/fonts")
configure_file(asset_path.h.in asset_path.h @ONLY)
target_include_directories(quietproof-prover-gui PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
install(TARGETS quietproof-prover-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES assets/Inter.ttf assets/Inter-OFL.txt
  DESTINATION ${CMAKE_INSTALL_DATADIR}/quietproof/fonts)
install(FILES vendor/LICENSE vendor/SDL-LICENSE.txt vendor/PROVENANCE.md BRANDING.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/quietproof-prover-gui)

if(BUILD_TESTING)
  add_executable(quietproof-gui-node-settings-test ${PROJECT_SOURCE_DIR}/tests/gui/node_settings_test.cc)
  target_link_libraries(quietproof-gui-node-settings-test PRIVATE quietproof-gui-node)
  add_test(NAME quietproof-gui-node-settings-test COMMAND quietproof-gui-node-settings-test
    ${CMAKE_CURRENT_BINARY_DIR}/node-fixtures)
  add_executable(quietproof-gui-request-test ${PROJECT_SOURCE_DIR}/tests/gui/request_test.cc)
  target_link_libraries(quietproof-gui-request-test PRIVATE quietproof-gui-request)
  add_test(NAME quietproof-gui-request-test COMMAND quietproof-gui-request-test
    ${CMAKE_CURRENT_BINARY_DIR}/request-fixtures)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_executable(quietproof-gui-node-probe-test ${PROJECT_SOURCE_DIR}/tests/gui/node_probe_test.cc)
  target_link_libraries(quietproof-gui-node-probe-test PRIVATE quietproof-gui-node)
  add_test(NAME quietproof-gui-node-probe-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/node_probe_fixture.py
      $<TARGET_FILE:quietproof-gui-node-probe-test> ${CMAKE_CURRENT_BINARY_DIR}/probe-artifacts)
  set_tests_properties(quietproof-gui-node-probe-test PROPERTIES TIMEOUT 90)
  add_test(NAME quietproof-gui-node-probe-ui-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/node_probe_ui_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/review-fixtures
      ${CMAKE_CURRENT_BINARY_DIR}/probe-ui-artifacts)
  set_tests_properties(quietproof-gui-node-probe-ui-test PROPERTIES TIMEOUT 120 FIXTURES_REQUIRED gui-review-files)
  add_test(NAME quietproof-gui-node-settings-ui-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/node_settings_ui_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/node-artifacts
      ${CMAKE_CURRENT_BINARY_DIR}/review-fixtures)
  set_tests_properties(quietproof-gui-node-settings-ui-test PROPERTIES TIMEOUT 120 FIXTURES_REQUIRED gui-review-files)
  add_executable(quietproof-gui-review-test ${PROJECT_SOURCE_DIR}/tests/gui/request_review_test.cc)
  target_link_libraries(quietproof-gui-review-test PRIVATE quietproof-gui-request)
  add_test(NAME quietproof-gui-review-test COMMAND quietproof-gui-review-test
    ${CMAKE_CURRENT_BINARY_DIR}/review-fixtures)
  set_tests_properties(quietproof-gui-review-test PROPERTIES FIXTURES_SETUP gui-review-files)
  add_test(NAME quietproof-gui-parity-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/request_parity_test.py
      $<TARGET_FILE:quietproof-cli> $<TARGET_FILE:quietproof-gui-review-test>
      ${CMAKE_CURRENT_BINARY_DIR}/review-fixtures)
  set_tests_properties(quietproof-gui-parity-test PROPERTIES FIXTURES_REQUIRED gui-review-files TIMEOUT 30)
  add_test(NAME quietproof-gui-review-ui-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/request_review_ui_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/review-fixtures
      ${CMAKE_CURRENT_BINARY_DIR}/review-artifacts)
  set_tests_properties(quietproof-gui-review-ui-test PROPERTIES FIXTURES_REQUIRED gui-review-files TIMEOUT 180)
  add_test(NAME quietproof-gui-request-ui-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/request_ui_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/request-fixtures
      ${CMAKE_CURRENT_BINARY_DIR}/request-artifacts)
  set_tests_properties(quietproof-gui-request-test PROPERTIES FIXTURES_SETUP gui-request-files)
  set_tests_properties(quietproof-gui-request-ui-test PROPERTIES
    FIXTURES_REQUIRED gui-request-files TIMEOUT 120)
  add_test(NAME quietproof-gui-lifecycle-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/lifecycle_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts)
  set_tests_properties(quietproof-gui-lifecycle-test PROPERTIES TIMEOUT 30)
  add_test(NAME quietproof-gui-build-contract-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/build_contract_test.py
      ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/contract-builds "${CMAKE_PREFIX_PATH}")
  set_tests_properties(quietproof-gui-build-contract-test PROPERTIES TIMEOUT 30)
  add_test(NAME quietproof-gui-shell-test
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/gui/shell_test.py
      $<TARGET_FILE:quietproof-prover-gui> ${CMAKE_CURRENT_BINARY_DIR}/shell-artifacts)
  set_tests_properties(quietproof-gui-shell-test PROPERTIES TIMEOUT 120)
endif()
