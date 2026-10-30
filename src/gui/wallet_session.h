#pragma once

#include "node_probe.h"
#include "request_review.h"
#include "quietproof/envelope.h"
#include "proof_output.h"

#include <functional>
#include <span>

namespace quietproof::gui {
// Owned key bytes never appear in session status. Use only on the owning worker.
class WalletKey final {
 public:
  WalletKey() = default;
  ~WalletKey();
  WalletKey(const WalletKey&) = delete;
  WalletKey& operator=(const WalletKey&) = delete;
  std::array<uint8_t,32>& Bytes() { return bytes_; }
 private:
  std::array<uint8_t,32> bytes_{};
};
struct WalletSessionJob {
  uint64_t revision;
  NodeConfiguration configuration;
  std::shared_ptr<const LoadedRequest> request;
  // nullopt is no selection; an empty string explicitly names the default wallet.
  std::optional<std::string> wallet;
  bool prove_approved = false;
};
enum class WalletSessionStatus { Failed, Canceled, PasswordRequired, Acquired, Proved };
enum class WalletCleanup { NotNeeded, Relocked, Failed };
struct WalletSessionResult {
  uint64_t revision = 0;
  std::optional<std::string> wallet;
  WalletSessionStatus status = WalletSessionStatus::Failed;
  WalletCleanup cleanup = WalletCleanup::NotNeeded;
  bool unlock_attempted = false;
  bool unlock_confirmed = false;
  proofs::BitcoinRpcError error;
  proofs::BitcoinRpcError cleanup_error;
  std::unique_ptr<WalletKey> key;
  // Public proof only. The owning worker erases the key before publication.
  std::unique_ptr<proofs::QuietProofEnvelopeV1> proof;
  std::shared_ptr<const VerifiedProof> verified;
  std::string Message() const;
};
// Worker-thread operation. Checks immutable request/time/network/script and the
// exact selected wallet before touching secrets. Empty password probes first and
// returns PasswordRequired only for a locked eligible wallet. On submission the
// complete probe is repeated; no unlock retry/extension. Cancellation must stay
// callable and nonthrowing, and report request/settings/wallet changes or close.
// clock supplies current Unix seconds, also checked after every slow operation.
// password_used is an optional nonthrowing owner-erasure callback, invoked when
// unlock input is consumed (or on an earlier exit). It must not invalidate its
// own callback storage. No password is needed again in this invocation.
WalletSessionResult RunWalletSession(const WalletSessionJob&,
    std::span<const char> password, const std::function<bool()>& canceled,
    const std::function<int64_t()>& clock,
    const std::function<void()>& password_used = {},
    const std::function<void(ProofStage)>& stage = {});
}  // namespace quietproof::gui
