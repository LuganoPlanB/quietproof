// SPDX-License-Identifier: GPL-3.0-or-later
#include "context.h"
using namespace proofs;
static_assert(!kQuietProofSignatureModeEnabled);
bool ConsumeLegacyBrowserContext(QuietProofBrowserVerification& context) {
  return context.phase() == QuietProofBrowserVerification::Phase::kPrepared &&
      !context.Verify(102) && context.unsupported() &&
      context.outcome().crypto == QuietProofBrowserCrypto::kNotChecked;
}
bool PrepareDisabledBrowserSignature(QuietProofBrowserVerification* context,
    const std::vector<uint8_t>& proof, const QuietProofBrowserPolicy& policy, uint64_t now) {
  return PrepareQuietProofBrowserSignature(context, proof, policy, now);
}
bool CheckPreparedBrowserContext(QuietProofBrowserVerification& context, uint64_t now) {
  return context.phase() == QuietProofBrowserVerification::Phase::kPrepared &&
      context.RecheckPolicy(now) && context.outcome().crypto == QuietProofBrowserCrypto::kNotChecked;
}
bool VerifyBrowserContextInDisabledTu(QuietProofBrowserVerification& context, uint64_t now) {
  return context.Verify(now);
}
