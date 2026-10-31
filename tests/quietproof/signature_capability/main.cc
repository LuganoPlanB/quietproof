// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include "probe.h"
#include <cstring>
#include <iostream>

namespace { size_t clock_calls = 0, random_calls = 0; }
bool SignatureProbeClock(uint64_t* now) { ++clock_calls; *now = 100; return true; }
int SignatureProbeRandom(void* output, size_t size) {
  ++random_calls; std::memset(output, 1, size); return 0;
}
int main() {
  const auto disabled = DisabledSignatureProbe();
  const bool disabled_ok = !disabled.capability && !disabled.public_result && !disabled.sourced_result && !disabled.digest_result &&
      disabled.expected_errors && disabled.unchanged_or_valid_output && disabled.receipt_capability_checked && disabled.envelope_capability_checked && clock_calls == 0 && random_calls == 0;
  const auto enabled = EnabledSignatureProbe();
  const bool enabled_ok = enabled.capability && enabled.public_result && enabled.sourced_result && enabled.digest_result &&
      enabled.expected_errors && enabled.unchanged_or_valid_output && enabled.receipt_capability_checked && enabled.envelope_capability_checked && clock_calls == 1 && random_calls == 1;
  std::cout << "disabled=" << disabled.public_result << " enabled=" << enabled.public_result
            << " disabled_seam=" << disabled.sourced_result << " enabled_seam=" << enabled.sourced_result
            << " disabled_digest=" << disabled.digest_result << " enabled_digest=" << enabled.digest_result << '\n';
  return disabled_ok && enabled_ok ? 0 : 1;
}
