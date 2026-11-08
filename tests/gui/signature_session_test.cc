#include "proof_session.h"
#include "private_input.h"
#include "shell.h"
#include "quietproof/signature_challenge.h"
#include <fstream>
#include <iostream>
#include <ctime>
#include <sys/stat.h>
#include <unistd.h>

using namespace quietproof::gui;
namespace fs = std::filesystem;
int main(int argc,char** argv) {
  if (argc < 2) return 1;
  const fs::path root(argv[1]);
  RequestState request; request.Open(root/"request.qpr");
  if (!request.loaded || !request.loaded->signature) return 2;
  const bool disabled=argc==3 && std::string(argv[2])=="--disabled";
  if (argc == 3 && !disabled) {
    std::ifstream input(argv[2],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    auto checked = ProofValidation::RunSignature(request.loaded,bytes,std::time(nullptr),[] { return false; });
    if (!checked.proof) return 3;
    std::cout << "GUI signature proof independently verified; exact request retained\n";
    return 0;
  }
  int checks = 0;
  auto require = [&](bool value) { ++checks; if (!value) throw std::runtime_error("GUI signature session contract failed"); };
  try {
    const auto clock = [] { return static_cast<int64_t>(std::time(nullptr)); };
    SignatureJob job{17,request.loaded,root/"receipt.qpa"};
    const auto canceled = RunSignatureSession(job,[] { return true; },clock);
    require(canceled.status == WalletSessionStatus::Canceled && !canceled.verified && !canceled.key);
    require(disabled != proofs::kQuietProofSignatureModeEnabled);
    if (disabled) {
      const auto unavailable=RunSignatureSession(job,[] { return false; },clock);
      require(unavailable.status==WalletSessionStatus::Failed && !unavailable.verified && !unavailable.key);
      require(unavailable.error.message.find("unsupported")!=std::string::npos);
      require(ProofValidation::RunSignature(request.loaded,{},clock(),[] { return false; }).error.find("unsupported")!=std::string::npos);
      std::cout << checks << " GUI disabled profile/receipt/no-fallback checks passed\n";
      return 0;
    }
    auto expired = RunSignatureSession(job,[] { return false; },[&] { return clock()+7200; });
    require(expired.status == WalletSessionStatus::Failed && !expired.verified);
    for (const auto path : {"missing.qpa","wrong.qpa","wrong-profile.qpa","v3.qpa","oversized.qpa","link.qpa","fifo.qpa"}) {
      job.receipt_path=root/path;
      const auto result=RunSignatureSession(job,[] { return false; },clock);
      require(result.status == WalletSessionStatus::Failed && !result.verified && !result.key);
      require(result.revision==17);
    }
    for(const auto path:{"v3.qpr","unknown-profile.qpr","future-profile.qpr"}){
      RequestState unsupported;unsupported.Open(root/path);
      require(!unsupported.loaded && unsupported.error==RequestError::Unsupported);
    }
    RequestState other;other.Open(root/"other-request.qpr");require(bool(other.loaded));
    job.request=other.loaded;job.receipt_path=root/"receipt.qpa";
    require(RunSignatureSession(job,[] { return false; },clock).status==WalletSessionStatus::Failed);
    job.request=request.loaded;
    bool stop=false;size_t stages=0;
    auto stopped=RunSignatureSession(job,[&]{return stop;},clock,[&](const ProofEvent& event){
      ++stages;if(event.stage==ProofStage::Prove)stop=true;
    });
    require(stopped.status==WalletSessionStatus::Canceled && !stopped.verified && !stopped.key && stages==2);
    ShellState state;state.request.loaded=request.loaded;state.node_probe.revision=job.revision;
    state.signature_job=job;state.wallet_busy=true;
    state.InvalidateNodeProbe();
    require(state.node_probe.revision!=job.revision && !state.signature_job && !state.completed_proof);
    require(state.wallet_cancel_pending && state.cancel_wallet && state.wallet_input->Size()==0);
    job.receipt_path=root/"receipt.qpa";
    for (const auto mode : {0644,0640,0606}) {
      chmod(job.receipt_path.c_str(),mode);
      auto result=RunSignatureSession(job,[] { return false; },clock);
      require(result.status == WalletSessionStatus::Failed && !result.verified);
    }
    chmod(job.receipt_path.c_str(),0600);
    RequestState legacy; legacy.Open(root/"legacy.qpr");
    require(legacy.loaded && !legacy.loaded->signature);
    job.request=legacy.loaded;
    require(RunSignatureSession(job,[] { return false; },clock).status == WalletSessionStatus::Failed);
    auto config=ConfigureNode({},request.loaded->Network(),nullptr);
    require(bool(config));
    WalletSessionJob old{18,*config,request.loaded,std::string("must-not-contact"),true};
    require(RunWalletSession(old,{},[] { return false; },clock).status == WalletSessionStatus::Failed);
    require(!ProofValidation::Run(request.loaded,{},[] { return false; },[](const auto&) { return true; }).proof);
    require(RequestWindowAt(*request.loaded,clock()) == RequestWindow::Valid);
    require(InspectRequest(*request.loaded).statement_version == 4);
    const auto review=InspectRequest(*request.loaded);
    require(review.profile_version==1 && review.proof_mode=="signature-possession" && !review.signing_address.empty());
    require(review.signing_profile==proofs::QuietProofSigningProfileName(request.loaded->signature->signing_profile));
    std::cout << checks << " GUI PoSC request/receipt/mode/privacy checks passed\n";
  } catch (...) { std::cerr << "GUI signature contract failed; private diagnostics suppressed\n"; return 1; }
}
