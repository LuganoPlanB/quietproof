// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_TEST_SIGNATURE_CAPABILITY_PROBE_H_
#define QUIETPROOF_TEST_SIGNATURE_CAPABILITY_PROBE_H_
#include <cstddef>
#include <cstdint>

struct SignatureCapabilityProbe {
  bool capability = false;
  bool public_result = false;
  bool sourced_result = false;
  bool digest_result = false;
  bool receipt_capability_checked = false;
  bool envelope_capability_checked = false;
  bool expected_errors = false;
  bool unchanged_or_valid_output = false;
};
SignatureCapabilityProbe DisabledSignatureProbe();
SignatureCapabilityProbe EnabledSignatureProbe();

// Both objects pass these exact external function pointers into the template
// seam. Their Clock/Random types match, exposing accidental shared instantiation.
bool SignatureProbeClock(uint64_t* now);
int SignatureProbeRandom(void* output, size_t size);
#endif
