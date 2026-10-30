#include "wallet_session.h"
#include "private_input.h"

#include "circuit/pokc_witness.h"
#include "ec/p256k1.h"

#include <algorithm>

namespace quietproof::gui {
namespace {
void Erase(void* pointer, size_t count) {
  volatile unsigned char* p = static_cast<unsigned char*>(pointer);
  while (count--) *p++ = 0;
}
using Code = proofs::BitcoinRpcErrorCode;
}
WalletKey::~WalletKey() { Erase(bytes_.data(),bytes_.size()); }
std::string WalletSessionResult::Message() const {
  if (cleanup == WalletCleanup::Failed)
    return "Wallet relock failed. The one-shot 15-second lease is the fallback; check and lock the selected wallet in your node. External clients can change that timeout.";
  if (unlock_attempted && !unlock_confirmed && cleanup == WalletCleanup::Relocked)
    return "Unlock response was lost or invalid. Relock was acknowledged, but late node processing can race it; check the selected wallet. A 15-second node lease is the fallback, unless another client changes it.";
  if (status == WalletSessionStatus::Canceled) return "Wallet access canceled; any app-owned unlock was relocked.";
  if (status == WalletSessionStatus::PasswordRequired)
    return "The selected wallet is locked. Enter its wallet password for one short unlock; RPC cookie authentication is separate.";
  if (status == WalletSessionStatus::Acquired) return "Request-matching key acquired; wallet cleanup completed.";
  return error.message;
}
WalletSessionResult RunWalletSession(const WalletSessionJob& job,
    std::span<const char> password, const std::function<bool()>& canceled,
    const std::function<int64_t()>& clock, const std::function<void()>& password_used) {
  WalletSessionResult result;
  result.revision = job.revision;
  result.wallet = job.wallet;
  struct PasswordUsed {
    const std::function<void()>& callback;
    bool used = false;
    void Run() { if (!used) { used = true; if (callback) callback(); } }
    ~PasswordUsed() { Run(); }
  } consumed{password_used};
  bool cleanup_needed = false;
  auto configuration = job.configuration.rpc;
  // Bound individual key/unlock/cleanup calls independently of advanced settings.
  configuration.rpc_timeout = std::min(configuration.rpc_timeout,std::chrono::milliseconds(5000));
  configuration.connect_timeout = std::min(configuration.connect_timeout,configuration.rpc_timeout);
  proofs::BitcoinCoreRpc rpc(configuration);
  auto fail = [&](Code code, const char* message) {
    result.error = {code,0,{},message};
  };
  auto current = [&] {
    if (canceled()) { result.status = WalletSessionStatus::Canceled; return false; }
    if (!job.request || RequestWindowAt(job.request->statement,clock()) != RequestWindow::Valid) {
      fail(Code::kConfiguration,"Request is outside its valid time window; no key retained");
      return false;
    }
    return true;
  };
  // The guard also handles an exceptional exit after an ambiguous unlock. It
  // always uses the captured instance and wallet, never mutable UI selection.
  struct Cleanup {
    proofs::BitcoinCoreRpc& rpc;
    const std::optional<std::string>& wallet;
    bool& needed;
    WalletSessionResult& result;
    void Run() noexcept {
      if (!needed) return;
      needed = false;
      result.cleanup = WalletCleanup::Failed;
      try {
        if (rpc.LockWallet(*wallet,&result.cleanup_error)) result.cleanup = WalletCleanup::Relocked;
      } catch (...) { result.cleanup_error = {Code::kConnection,0,{},"Wallet relock failed; private diagnostics suppressed"}; }
      if (result.cleanup == WalletCleanup::Failed) {
        result.key.reset();
        if (result.status == WalletSessionStatus::Acquired) result.status = WalletSessionStatus::Failed;
      }
    }
    ~Cleanup() { Run(); }
  } cleanup{rpc,job.wallet,cleanup_needed,result};
  try {
    do {
      if (!job.prove_approved || !job.wallet || !job.request ||
          job.request->statement.network != configuration.network) {
        fail(Code::kConfiguration,"Explicit Prove approval, a request and matching selected wallet/network are required"); break;
      }
      if (!current()) break;
      const auto match = MatchRequest(*job.request);
      if (!match) { fail(Code::kUnsupportedScript,"Request requires unsupported or distinct keys"); break; }
      proofs::BitcoinRpcProbe probe;
      if (!rpc.Probe(match,&probe,&result.error,std::chrono::milliseconds(10000))) break;
      if (!current()) break;
      const auto found = std::find_if(probe.wallets.begin(),probe.wallets.end(),[&](const auto& w) { return w.name == *job.wallet; });
      NodeProbeResult eligibility;
      eligibility.complete = true; eligibility.has_request = true; eligibility.supported_request = true; eligibility.probe = probe;
      if (probe.syncing != false || found == probe.wallets.end() || !eligibility.Eligible(*found)) {
        fail(Code::kUnsupportedWallet,"Selected wallet, network or request export capability is unavailable"); break;
      }
      proofs::BitcoinRpcWalletState state;
      if (!rpc.WalletState(*job.wallet,&state,&result.error) || !current()) break;
      if (state == proofs::BitcoinRpcWalletState::kLocked) {
        if (password.empty()) { result.status = WalletSessionStatus::PasswordRequired; break; }
        // Mark before dispatch: a lost reply does not establish unlock failure.
        cleanup_needed = true;
        result.unlock_attempted = true;
        const bool unlocked = rpc.UnlockWallet(*job.wallet,password,std::chrono::seconds(15),&result.error);
        consumed.Run();
        if (!unlocked) {
          // These definitive node rejections cannot have unlocked the wallet.
          if (result.error.code == Code::kWrongPassphrase || result.error.code == Code::kUnsupportedWallet ||
              result.error.code == Code::kCookie)
            cleanup_needed = false;
          break;
        }
        result.unlock_confirmed = true;
      }
      consumed.Run();
      if (!current()) break;
      auto key = std::make_unique<WalletKey>();
      if (!rpc.ExportSelectedAddressKey(*job.wallet,*match,&key->Bytes(),&result.error,[&] { return !current(); })) {
        if (result.error.rpc_code == -13) {
          result.error.code = Code::kWalletLocked;
          result.error.message = "Wallet locked during export. Start a new attempt explicitly";
        } else if (result.error.rpc_code == -32601) {
          result.error.code = Code::kUnsupportedWallet;
          result.error.message = "Node does not support Roots address-key export. Full Core proving is deferred";
        }
        break;
      }
      // Relock promptly, before key validation or later proof work.
      cleanup.Run();
      if (result.cleanup == WalletCleanup::Failed || !current()) break;
      proofs::PoKCWitnessV1<proofs::Fp256k1Base,proofs::P256k1> witness;
      struct EraseWitness {
        decltype(witness)& value;
        ~EraseWitness() { Erase(&value,sizeof(value)); }
      } erase_witness{witness};
      const bool valid = witness.compute(proofs::p256k1,key->Bytes().data(),key->Bytes().size());
      const bool matches = valid && witness.program() == match->program;
      if (!matches) { fail(Code::kInvalidAddress,"Exported key is invalid or does not match the reviewed request"); break; }
      if (!current()) break;
      result.key = std::move(key);
      result.status = WalletSessionStatus::Acquired;
    } while (false);
  } catch (...) { fail(Code::kConnection,"Wallet session failed; private diagnostics suppressed"); }
  cleanup.Run();
  return result;
}
bool NodeProbeWorker::StartWallet(WalletSessionJob job, std::unique_ptr<PrivateInput> password) {
  if (running_.load() || !password) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); wallet_result_.reset(); }
  canceled_.store(false);
  running_.store(true);
  try {
    thread_ = std::thread([this,job=std::move(job),password=std::move(password)] {
      auto result = std::make_unique<WalletSessionResult>();
      try {
        *result = RunWalletSession(job,password->Bytes(),[this] { return canceled_.load(); },[] {
          return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        },[&] { password->Clear(); });
      } catch (...) {
        result->revision = job.revision; result->wallet = job.wallet;
        result->error = {Code::kConnection,0,{},"Wallet access failed; private diagnostics suppressed"};
      }
      password->Clear();
      // L4 validates acquisition only. L5 will consume the key inside this same
      // worker; no key bytes cross into the UI/event queue in this milestone.
      result->key.reset();
      { std::lock_guard lock(mutex_); wallet_result_ = std::move(result); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
std::unique_ptr<WalletSessionResult> NodeProbeWorker::PollWallet() {
  std::lock_guard lock(mutex_);
  return std::move(wallet_result_);
}
}  // namespace quietproof::gui
