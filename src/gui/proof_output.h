#pragma once

#include "request.h"
#include "quietproof/envelope.h"

#include <functional>
#include <span>

namespace quietproof::gui {
class VerifiedProof final {
 public:
  const LoadedRequest& Request() const { return *request_; }
  const std::vector<uint8_t>& Bytes() const { return bytes_; }
  uint64_t CreatedAt() const { return created_at_; }
 private:
  VerifiedProof(std::shared_ptr<const LoadedRequest> request, std::vector<uint8_t> bytes, uint64_t created)
      : request_(std::move(request)), bytes_(std::move(bytes)), created_at_(created) {}
  const std::shared_ptr<const LoadedRequest> request_;
  const std::vector<uint8_t> bytes_;
  const uint64_t created_at_;
  friend struct ProofValidation;
};
using ProofVerifier = std::function<bool(const proofs::QuietProofEnvelopeV1&)>;
struct ProofValidation {
  std::shared_ptr<const VerifiedProof> proof;
  std::string error;
  // The test verifier replaces only cryptographic work; exact statement and
  // envelope checks remain mandatory. Production uses native PoKCVerifyProof.
  static ProofValidation Run(std::shared_ptr<const LoadedRequest>,
      const proofs::QuietProofEnvelopeV1&, const std::function<bool()>& canceled,
      const ProofVerifier& test_verifier = {});
};
struct ValidationJob {
  uint64_t revision;
  std::shared_ptr<const LoadedRequest> request;
  std::filesystem::path proof_path;
};
struct OutputIdentity {
  uint64_t device, inode, size;
  int64_t modified_seconds, modified_nanos, changed_seconds, changed_nanos;
  std::filesystem::path destination;
  friend bool operator==(const OutputIdentity&, const OutputIdentity&) = default;
};
struct SaveJob {
  const uint64_t revision;
  const uint64_t attempt;
  const std::shared_ptr<const VerifiedProof> proof;
  const std::filesystem::path destination;
  const std::optional<OutputIdentity> replace;
};
enum class SaveStatus { Saved, NeedsOverwrite, Canceled, Failed, DestinationChanged };
struct SaveResult {
  uint64_t revision = 0, attempt = 0;
  std::filesystem::path destination;
  SaveStatus status = SaveStatus::Failed;
  std::optional<OutputIdentity> existing;
  bool committed = false;
  bool durability_warning = false;
  bool cleanup_failed = false;
  std::string message;
};
enum class SavePoint { TemporaryCreated, Written, BeforeCommit, Committed };
struct SaveHooks {
  // Deterministic test seams. Callbacks never receive key/password material.
  std::function<void(SavePoint)> observe;
  std::function<ptrdiff_t(int,std::span<const uint8_t>)> write;
  std::function<int(int)> sync;
  std::function<int(int)> sync_directory;
};
SaveResult RunSave(const SaveJob&, const std::function<bool()>& canceled,
    const SaveHooks& hooks = {});
}  // namespace quietproof::gui
