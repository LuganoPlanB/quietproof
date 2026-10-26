// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <wasi/api.h>

#include "util/crypto.h"

// Bootstrap ABI only. No request, verifier or prover entry points yet.
extern "C" uint32_t quietproof_wasm_abi_version() { return 1; }

extern "C" void* quietproof_wasm_alloc(uint32_t size) {
  constexpr uint32_t kMaxBootstrapAllocation = 16 * 1024 * 1024;
  if (size == 0 || size > kMaxBootstrapAllocation) return nullptr;
  return std::malloc(size);
}

extern "C" void quietproof_wasm_free(void* allocation) {
  std::free(allocation);
}

// Caller owns a 72-byte allocation: entropy[32], untrusted realtime_ns[8]
// (little endian), then SDK SHA256(entropy || realtime_ns)[32]. Returns
// 0=success, 1=invalid output size, 2=entropy unavailable, 3=clock unavailable.
// Output is cleared on host failure; there is no fallback entropy or clock.
extern "C" uint32_t quietproof_wasm_smoke(uint8_t* output, uint32_t size) {
  if (output == nullptr || size != 72) return 1;
  std::memset(output, 0, size);
  std::array<uint8_t, 40> input{};
  if (__wasi_random_get(input.data(), 32) != 0) return 2;
  __wasi_timestamp_t now = 0;
  if (__wasi_clock_time_get(__WASI_CLOCKID_REALTIME, 1000000, &now) != 0)
    return 3;
  for (uint32_t i = 0; i < 8; ++i)
    input[32 + i] = static_cast<uint8_t>(now >> (8 * i));
  proofs::SHA256 hash;
  hash.Update(input.data(), input.size());
  hash.DigestData(output + input.size());
  std::memcpy(output, input.data(), input.size());
  return 0;
}
