find_package(SDL2 2.0.22 CONFIG REQUIRED)

add_executable(quietproof-prover-gui main.cc application.cc preferences.cc theme.cc shell.cc nuklear_backend.cc)
set_target_properties(quietproof-prover-gui PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
target_compile_features(quietproof-prover-gui PRIVATE cxx_std_20)
target_link_libraries(quietproof-prover-gui PRIVATE
  LongfellowZKQuietProof::rpc SDL2::SDL2)
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
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
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
