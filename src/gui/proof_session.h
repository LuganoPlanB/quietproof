#pragma once

#include "wallet_session.h"

namespace quietproof::gui {
// An approved snapshot. Settings/request/wallet edits cannot change this job.
struct ProofJob {
  const WalletSessionJob session;
};
using ProofProgress = std::function<void(const ProofEvent&)>;
// The optional generator is a test seam for deterministic step failures/holds.
// Production always uses the existing native PoKCProve implementation.
using ProofGenerator = std::function<bool(const std::array<uint8_t,32>&,
    const proofs::QuietProofStatementV1&, proofs::QuietProofEnvelopeV1*,
    const std::function<void(ProofPhase)>&)>;
WalletSessionResult RunProofSession(const ProofJob&, std::span<const char>,
    const std::function<bool()>& canceled, const std::function<int64_t()>& clock,
    const std::function<void()>& password_used, const ProofProgress&,
    const ProofGenerator& generator = {}, const ProofVerifier& test_verifier = {});
}  // namespace quietproof::gui
