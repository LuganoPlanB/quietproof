#include "proof_session.h"
#include "private_input.h"
#include "quietproof/signature_challenge.h"
#include "poksig/prover.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string_view>

namespace quietproof::gui {
namespace {
struct PrivateReceipt {
  std::vector<uint8_t> bytes;
  ~PrivateReceipt() { ErasePrivateMemory(bytes.data(),bytes.size()); }
};
bool ReadReceipt(const std::filesystem::path& path, PrivateReceipt& receipt) {
  const int fd = open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
  if (fd < 0) return false;
  struct Close { int fd; ~Close() { close(fd); } } close_file{fd};
  struct stat s{};
  if (fstat(fd,&s) != 0 || !S_ISREG(s.st_mode) || s.st_uid != geteuid() ||
      (s.st_mode&077) || s.st_size <= 0 ||
      static_cast<uint64_t>(s.st_size) > proofs::kQuietProofSignatureMaxReceiptBytes) return false;
  receipt.bytes.resize(static_cast<size_t>(s.st_size));
  size_t position = 0;
  while (position < receipt.bytes.size()) {
    const auto n = read(fd,receipt.bytes.data()+position,receipt.bytes.size()-position);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    position += static_cast<size_t>(n);
  }
  uint8_t extra = 0;
  return read(fd,&extra,1) == 0;
}
}
WalletSessionResult RunSignatureSession(const SignatureJob& job,
    const std::function<bool()>& canceled, const std::function<int64_t()>& clock,
    const ProofProgress& progress) {
  WalletSessionResult result; result.revision = job.revision;
  auto fail = [&](const char* message) {
    result.status = WalletSessionStatus::Failed;
    result.error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},message};
  };
  auto current = [&] {
    if (canceled()) { result.status = WalletSessionStatus::Canceled; return false; }
    if (!job.request || !job.request->signature ||
        RequestWindowAt(*job.request,clock()) != RequestWindow::Valid) {
      fail("PoSC requires a valid signature-custody request; select legacy PoKC explicitly for v1/v2"); return false;
    }
    return true;
  };
  const auto started = std::chrono::steady_clock::now();
  auto emit = [&](ProofStage stage, ProofPhase phase = ProofPhase::None) {
    if (progress) progress({job.revision,stage,phase,
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started)});
  };
  try {
    if (!current()) return result;
    if (!proofs::kQuietProofSignatureModeEnabled) { fail("Signature custody is unsupported in this build; no private-key fallback is performed"); return result; }
    emit(ProofStage::Validation);
    PrivateReceipt receipt;
    if (!ReadReceipt(job.receipt_path,receipt)) {
      fail("Private receipt must be a current-owner owner-only regular file, at most 4096 bytes; links are rejected"); return result;
    }
    if (!current()) return result;
    proofs::PoKSigOptionsV1 policy; policy.allow_signature_possession = true;
    proofs::PoKSigProofV1 proof;
    proofs::PoKSigError error;
    emit(ProofStage::Prove);
    const bool proved = proofs::PoKSigProveReceipt(job.request->bytes,receipt.bytes,&proof,policy,&error,
        [&](const char* name) {
          const std::string_view phase(name);
          emit(ProofStage::Prove,phase.find("circuit") != phase.npos ? ProofPhase::Circuit :
              phase.find("committing") != phase.npos ? ProofPhase::Commitment : ProofPhase::Generation);
        });
    ErasePrivateMemory(receipt.bytes.data(),receipt.bytes.size());
    if (!current()) return result;
    if (!proved) { fail("Signature receipt does not authorize this exact request, or signature proof generation failed"); return result; }
    emit(ProofStage::Verify);
    auto validated = ProofValidation::RunSignature(job.request,proof.bytes,static_cast<uint64_t>(clock()),canceled);
    if (!current()) return result;
    if (!validated.proof) { fail(validated.error.c_str()); return result; }
    result.verified = std::move(validated.proof); result.status = WalletSessionStatus::Proved;
    emit(ProofStage::Completion);
  } catch (...) { fail("Signature proof work failed; private diagnostics suppressed"); }
  return result;
}
bool NodeProbeWorker::StartSignature(SignatureJob job) {
  if (running_.load()) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); wallet_result_.reset(); save_result_.reset(); progress_.reset(); }
  canceled_.store(false); running_.store(true);
  try {
    thread_ = std::thread([this,job=std::move(job)] {
      auto result = std::make_unique<WalletSessionResult>();
      *result = RunSignatureSession(job,[this] { return canceled_.load(); },[] {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
      },[this](const ProofEvent& event) { std::lock_guard lock(mutex_); progress_ = event; });
      { std::lock_guard lock(mutex_); wallet_result_ = std::move(result); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
}  // namespace quietproof::gui
