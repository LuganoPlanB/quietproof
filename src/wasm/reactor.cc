// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later

// libc++ supports customizing its fatal termination handler. In a worker a
// fatal STL precondition/allocation failure traps and discards the instance;
// it must not drag diagnostic FILE operations into the browser import surface.
#define _LIBCPP_VERBOSE_ABORT(...) __builtin_trap()

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <wasi/api.h>

#include "quietproof/browser.h"
#include "quietproof/browser_verifier.h"
#include "util/crypto.h"

// Compiled libc++ routines use the same overridable fatal handler.
namespace std { inline namespace _LIBCPP_ABI_NAMESPACE {
[[noreturn]] void __libcpp_verbose_abort(const char*, ...) noexcept {
  __builtin_trap();
}
} }

// No exceptions are enabled. Exhaustion is a fatal worker failure; replace the
// standard allocator's diagnostic abort path with a WebAssembly trap.
void* operator new(size_t size) {
  if (void* pointer = std::malloc(size ? size : 1)) return pointer;
  __builtin_trap();
}
void* operator new[](size_t size) { return ::operator new(size); }

namespace {
std::map<void*, uint32_t> allocations;
std::vector<uint8_t> result;
const char* last_error = "";
std::unique_ptr<proofs::QuietProofBrowserVerification> verification;
uint32_t context_id = 0;
bool realtime(uint64_t* seconds) {
  __wasi_timestamp_t now;
  if (__wasi_clock_time_get(__WASI_CLOCKID_REALTIME, 1000000, &now)) return false;
  *seconds = now / 1000000000;
  return true;
}
bool owned(const void* pointer, uint32_t size) {
  auto found = allocations.find(const_cast<void*>(pointer));
  return found != allocations.end() && size && size <= found->second;
}
uint32_t fail(const char* message, uint32_t status = 1) {
  result.clear();
  last_error = message;
  return status;
}
uint32_t verification_result() {
  const auto& out = verification->outcome();
  result.assign({'Q','W','R','1'});
  proofs::QuietProofAppendU32(&result, context_id);
  result.push_back(static_cast<uint8_t>(verification->phase()));
  result.push_back(static_cast<uint8_t>(out.crypto));
  result.push_back(static_cast<uint8_t>(out.policy));
  result.push_back(static_cast<uint8_t>(out.explorer));
  proofs::QuietProofAppendU64(&result, out.total_sats);
  // Only a cryptographically valid, policy-bound context exposes a fetchable
  // manifest. Failed/unverified contexts cannot trigger a provider lookup.
  if (verification->phase() == proofs::QuietProofBrowserVerification::Phase::kVerified) {
    const auto& metadata = verification->metadata();
    result.insert(result.end(), metadata.begin(), metadata.end());
  }
  return 0;
}
}  // namespace

extern "C" uint32_t quietproof_wasm_abi_version() { return 2; }

extern "C" void* quietproof_wasm_alloc(uint32_t size) {
  if (size == 0 || size > proofs::kQuietProofMaxEnvelopeBytes) return nullptr;
  void* pointer = std::malloc(size);
  if (pointer) allocations.emplace(pointer, size);
  return pointer;
}

extern "C" void quietproof_wasm_free(void* allocation) {
  auto found = allocations.find(allocation);
  if (found == allocations.end()) return;
  allocations.erase(found);
  std::free(allocation);
}

extern "C" const uint8_t* quietproof_wasm_result_data() { return result.data(); }
extern "C" uint32_t quietproof_wasm_result_size() { return result.size(); }
extern "C" const char* quietproof_wasm_error_data() { return last_error; }
extern "C" uint32_t quietproof_wasm_error_size() { return std::strlen(last_error); }

extern "C" void quietproof_wasm_reset() {
  verification.reset(); result.clear(); last_error = "";
}

extern "C" uint32_t quietproof_wasm_prepare(const uint8_t* proof, uint32_t proof_size,
                                           const uint8_t* policy, uint32_t policy_size) {
  quietproof_wasm_reset();
  if (context_id == UINT32_MAX) return fail("Context identifiers exhausted; recreate worker");
  ++context_id; // Invalidates all previous phases even on failed preparation.
  if (!owned(proof, proof_size) || proof_size > proofs::kQuietProofMaxEnvelopeBytes ||
      !owned(policy, policy_size) || policy_size > 8192) return fail("Invalid verification input");
  proofs::QuietProofBrowserPolicy expected;
  if (!proofs::DecodeQuietProofBrowserPolicy(std::vector<uint8_t>(policy, policy + policy_size), &expected))
    return fail("Independent expected policy is required", 4);
  proofs::QuietProofEnvelopeV1 envelope;
  if (!proofs::DecodeQuietProofEnvelope(std::vector<uint8_t>(proof, proof + proof_size), &envelope))
    return fail("Malformed or unsupported proof");
  uint64_t now;
  if (!realtime(&now)) return fail("Browser clock unavailable", 3);
  verification = std::make_unique<proofs::QuietProofBrowserVerification>();
  if (!verification->Prepare(std::move(envelope), std::move(expected), now))
    return fail(verification->error(), verification->unsupported() ? 5 : 4);
  return verification_result();
}

extern "C" uint32_t quietproof_wasm_verify(uint32_t context) {
  result.clear(); last_error = "";
  if (!verification || context != context_id) return fail("Stale verification context");
  if (verification->phase() != proofs::QuietProofBrowserVerification::Phase::kPrepared)
    return fail("Invalid verification phase");
  uint64_t now;
  if (!realtime(&now)) { verification.reset(); return fail("Browser clock unavailable", 3); }
  if (!verification->Verify(now)) return fail(verification->error(), verification->unsupported() ? 5 : 4);
  if (!realtime(&now)) { verification.reset(); return fail("Browser clock unavailable", 3); }
  if (!verification->RecheckPolicy(now)) return fail(verification->error(), 4);
  return verification_result();
}

extern "C" uint32_t quietproof_wasm_evaluate(uint32_t context, const uint8_t* input, uint32_t size) {
  result.clear(); last_error = "";
  if (!verification || context != context_id) return fail("Stale evidence context");
  if (!owned(input, size) || size > 4096) { verification.reset(); return fail("Invalid evidence buffer"); }
  uint64_t now;
  if (!realtime(&now)) { verification.reset(); return fail("Browser clock unavailable", 3); }
  if (!verification->Evaluate(std::vector<uint8_t>(input, input + size), now))
    return fail(verification->error());
  return verification_result();
}

// Input must belong to alloc and remain live for the call. Results/errors are
// borrowed until the next operation; callers copy before freeing input or
// issuing another operation. Failed calls always clear the previous result.
extern "C" uint32_t quietproof_wasm_create_request(const uint8_t* input,
                                                   uint32_t size) {
  result.clear(); last_error = "";
  if (!owned(input, size) || size > proofs::kQuietProofBrowserMaxOptionsBytes)
    return fail("Invalid request options buffer");
  const std::vector<uint8_t> bytes(input, input + size);
  proofs::QuietProofChallengeOptions options;
  std::vector<proofs::QuietProofClaimV1> claims;
  if (!proofs::DecodeQuietProofBrowserOptions(bytes, &options, &claims))
    return fail("Malformed request options");
  proofs::QuietProofStatementV1 statement;
  proofs::QuietProofChallengeError error;
  const auto clock = [](uint64_t* seconds) {
    __wasi_timestamp_t now;
    if (__wasi_clock_time_get(__WASI_CLOCKID_REALTIME, 1000000, &now)) return false;
    *seconds = now / 1000000000;
    return true;
  };
  const auto random = [](uint8_t* bytes, size_t count) {
    return __wasi_random_get(bytes, count);
  };
  if (!proofs::quietproof_detail::CreateQuietProofChallengeWithSources(
          claims, options, &statement, &error, clock, random)) {
    if (error == proofs::QuietProofChallengeError::kRandom)
      return fail("Secure randomness unavailable", 2);
    if (error == proofs::QuietProofChallengeError::kClock)
      return fail("Browser clock unavailable", 3);
    return fail("Invalid request options or claims");
  }
  if (!proofs::EncodeQuietProofStatement(statement, &result))
    return fail("Request encoding failed");
  return 0;
}

extern "C" uint32_t quietproof_wasm_inspect(const uint8_t* input, uint32_t size,
                                           uint32_t proof) {
  result.clear(); last_error = "";
  const size_t maximum = proof ? proofs::kQuietProofMaxEnvelopeBytes :
                                proofs::kQuietProofMaxStatementBytes;
  if (proof > 1 || !owned(input, size) || size > maximum)
    return fail("Invalid inspection buffer");
  const std::vector<uint8_t> bytes(input, input + size);
  if (!proofs::QuietProofBrowserInspect(bytes, proof, &result))
    return fail("Malformed request or proof");
  return 0;
}

// Caller owns a 72-byte allocation: entropy[32], untrusted realtime_ns[8]
// (little endian), then SDK SHA256(entropy || realtime_ns)[32]. Returns
// 0=success, 1=invalid output size, 2=entropy unavailable, 3=clock unavailable.
// Output is cleared on host failure; there is no fallback entropy or clock.
extern "C" uint32_t quietproof_wasm_smoke(uint8_t* output, uint32_t size) {
  result.clear(); last_error = "";
  if (!owned(output, size) || size != 72) return 1;
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
