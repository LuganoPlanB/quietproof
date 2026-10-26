# WASI SDK 34 uses wasm32-wasip1 paths; the pinned Longfellow toolchain's
# legacy wasm32-wasi triple cannot locate that release's libc++ headers.
set(WASI_SDK_PATH "$ENV{WASI_SDK_PATH}" CACHE PATH "WASI SDK root")
if(NOT WASI_SDK_PATH)
  set(WASI_SDK_PATH "/opt/wasi-sdk" CACHE PATH "WASI SDK root" FORCE)
endif()
include("${WASI_SDK_PATH}/share/cmake/wasi-sdk-p1.cmake")
set(CMAKE_SYSROOT "${WASI_SDK_PATH}/share/wasi-sysroot")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_CXX_FLAGS_INIT "-msimd128 -fno-exceptions -fno-rtti")
