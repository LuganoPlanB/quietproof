// SPDX-License-Identifier: GPL-3.0-or-later
#include "context.h"
using namespace proofs;
static_assert(kQuietProofSignatureModeEnabled);
bool PrepareEnabledBrowserSignature(QuietProofBrowserVerification* context,
    const std::vector<uint8_t>& proof, const QuietProofBrowserPolicy& policy, uint64_t now) {
  return PrepareQuietProofBrowserSignature(context, proof, policy, now);
}
