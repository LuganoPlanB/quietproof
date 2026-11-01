// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "quietproof/browser_verifier.h"

// These declarations intentionally expose the pre-existing context by pointer
// and reference across translation units. A TU-local context cannot link them.
bool ConsumeLegacyBrowserContext(proofs::QuietProofBrowserVerification&);
bool PrepareEnabledBrowserSignature(proofs::QuietProofBrowserVerification*,
    const std::vector<uint8_t>&, const proofs::QuietProofBrowserPolicy&, uint64_t);
bool PrepareDisabledBrowserSignature(proofs::QuietProofBrowserVerification*,
    const std::vector<uint8_t>&, const proofs::QuietProofBrowserPolicy&, uint64_t);
bool CheckPreparedBrowserContext(proofs::QuietProofBrowserVerification&, uint64_t);
bool VerifyBrowserContextInDisabledTu(proofs::QuietProofBrowserVerification&, uint64_t);
