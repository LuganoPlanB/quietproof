#include "proof_session.h"
#include "private_input.h"
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
  if (argc == 3) {
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
    auto expired = RunSignatureSession(job,[] { return false; },[&] { return clock()+7200; });
    require(expired.status == WalletSessionStatus::Failed && !expired.verified);
    for (const auto path : {"missing.qpa","wrong.qpa","oversized.qpa","link.qpa","fifo.qpa"}) {
      job.receipt_path=root/path;
      const auto result=RunSignatureSession(job,[] { return false; },clock);
      require(result.status == WalletSessionStatus::Failed && !result.verified && !result.key);
    }
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
    require(InspectRequest(*request.loaded).statement_version == 3);
    std::cout << checks << " GUI PoSC request/receipt/mode/privacy checks passed\n";
  } catch (...) { std::cerr << "GUI signature contract failed; private diagnostics suppressed\n"; return 1; }
}
