#include "proof_session.h"
#include "private_input.h"
#include "pokc/prover.h"

#include <atomic>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace quietproof::gui;
using namespace proofs;
namespace {
int checks = 0;
void Check(bool value, const char* label) { ++checks; if (!value) throw std::runtime_error(label); }
QuietProofStatementV1 Statement() {
  QuietProofStatementV1 s;
  s.network = QuietProofNetwork::kRegtest; s.verifier = "proof-session.example";
  s.purpose = "proof-of-control"; s.nonce[0] = 1; s.bip322_message_hash[0] = 2;
  s.not_before = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()-100;
  s.expires_at = s.not_before+3600;
  QuietProofClaimV1 c; c.txid[0] = 1; c.amount_sats = 1;
  c.program = {0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
               0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6};
  s.claims.push_back(c); return s;
}
}
int main(int argc, char** argv) {
  try {
    Check(argc == 5,"arguments");
    const std::string scenario = argv[3];
    NodeConfiguration config{BitcoinCoreRpcConfig(QuietProofNetwork::kRegtest),{},{}};
    config.rpc.rpc_url = argv[1]; config.rpc.rpc_cookie = argv[2];
    config.rpc.rpc_timeout = config.rpc.connect_timeout = std::chrono::milliseconds(3000);
    const auto statement = Statement();
    std::vector<uint8_t> wire; Check(EncodeQuietProofStatement(statement,&wire),"encode immutable request");
    auto request = std::make_shared<const LoadedRequest>(LoadedRequest{{},wire,statement});
    ProofJob job{{17,config,request,"primary",true}};
    std::atomic<bool> canceled{scenario == "cancel-before"};
    PrivateInput password;
    std::array<char,12> synthetic{};
    for (size_t i=0;i<synthetic.size();++i) synthetic[i] = static_cast<char>(65+i);
    Check(password.Append({synthetic.data(),synthetic.size()}),"private input accepted");
    ErasePrivateMemory(synthetic.data(),synthetic.size());
    int generated = 0; bool expired = false;
    auto clock = [&] { return expired ? static_cast<int64_t>(statement.expires_at) : static_cast<int64_t>(statement.not_before+100); };
    std::vector<ProofEvent> stages;
    auto progress = [&](const ProofEvent& event) {
      Check(event.revision == 17,"progress binds revision");
      Check(stages.empty() || event.elapsed >= stages.back().elapsed,"elapsed monotonic");
      stages.push_back(event);
      if (scenario == "cancel-after-validation" && event.stage == ProofStage::Validation) canceled.store(true);
      if (scenario == "cancel-unlock" && event.stage == ProofStage::Unlock) canceled.store(true);
      if (scenario == "cancel-prove-entry" && event.stage == ProofStage::Prove) canceled.store(true);
    };
    const bool native = scenario.starts_with("native-");
    const bool held = scenario == "cancel-proof" || scenario == "throw-proof" || scenario == "close-proof" || scenario == "native-cancel";
    auto generator = [&](const auto& secret,const auto& s,auto* out,const auto& phase) {
      ++generated;
      Check(password.Size() == 0,"password erased before proof");
      Check(secret[31] == 1,"worker consumes validated synthetic key");
      std::vector<uint8_t> actual; Check(EncodeQuietProofStatement(s,&actual) && actual == request->bytes,"exact immutable reviewed statement passed to prover");
      auto hold = [&] {
        std::cout << "proof-held" << std::endl; std::cin.get();
        canceled.store(true);
        std::cout << "invalidated" << std::endl; std::cin.get();
      };
      if (!native) phase(ProofPhase::Commitment);
      if (held && !native) hold();
      if (scenario == "throw-proof" || scenario == "generation-exception") throw std::runtime_error("private generator diagnostic");
      if (native) return PoKCProve(secret,s,out,[&](const char* name) {
        if (std::string_view(name) == "computing commitment" && held) {
          phase(ProofPhase::Commitment); hold();
        }
        if (std::string_view(name) == "generating proof") phase(ProofPhase::Generation);
      });
      if (scenario == "generation-failure") return false;
      out->statement = s; out->envelope_version = 2;
      out->proof_created_at = s.not_before+100; out->proof.bytes = {1};
      out->proof.circuit_digest[0] = 1;
      if (scenario == "expires-proof") expired = true;
      if (scenario == "cancel-completion") canceled.store(true);
      return true;
    };
    WalletSessionResult result;
    if (scenario == "worker-cancel" || scenario == "worker-close" || scenario == "native-worker-late") {
      auto worker = std::make_unique<NodeProbeWorker>();
      auto input = std::make_unique<PrivateInput>();
      Check(input->Append({password.Bytes().data(),password.Bytes().size()}),"worker input ownership"); password.Clear();
      Check(worker->StartProof(job,std::move(input)),"proof worker starts");
      if (scenario != "native-worker-late") {
        std::cout << "started" << std::endl; std::cin.get();
        Check(!worker->StartProof(job,std::make_unique<PrivateInput>()),"repeated proof refused");
        Check(!worker->StartWallet(job.session,std::make_unique<PrivateInput>()),"wallet operation cannot overlap proof");
        Check(!worker->Start(NodeProbeJob{18,config,{},false,{}}),"probe cannot overlap proof");
        Check(worker->PollProgress().has_value() && !worker->PollProgress(),"bounded coalesced progress event");
        worker->CancelWallet();
        std::cout << "invalidated" << std::endl; std::cin.get();
      }
      if (scenario == "worker-close") worker.reset();
      else {
        const auto until = std::chrono::steady_clock::now()+std::chrono::seconds(scenario == "native-worker-late" ? 240 : 6);
        while (worker->Running() && std::chrono::steady_clock::now()<until) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        Check(!worker->Running(),"canceled worker settles");
        if (scenario == "native-worker-late") {
          const auto event = worker->PollProgress();
          Check(event && event->stage == ProofStage::Completion && !worker->PollProgress(),"late completion event remains bounded");
          worker->CancelWallet(); // Cancel between publication and UI polling.
        }
        auto value = worker->PollWallet();
        Check(value && value->status == WalletSessionStatus::Canceled && !value->key && !value->proof && !value->verified,"worker never publishes canceled proof/key");
        Check(value->cleanup == WalletCleanup::Relocked,"captured wallet cleanup settles");
        Check(!worker->PollWallet(),"result published once");
      }
    } else {
      const ProofVerifier verifier = native ? ProofVerifier{} : ProofVerifier{[](const auto&) { return true; }};
      result = RunProofSession(job,password.Bytes(),[&] { return canceled.load(); },clock,[&] { password.Clear(); },progress,generator,verifier);
      Check(password.Size() == 0 && !result.key,"input and key erased before publication");
      if (scenario == "success" || scenario == "native-success") {
        Check(result.status == WalletSessionStatus::Proved && result.proof && result.verified,"completed verified proof retained");
        Check(generated == 1 && stages.back().stage == ProofStage::Completion,"exactly one generator and completion");
        if (native) {
          Check(PoKCVerifyProof(*result.proof),"real native generated proof verifies");
          std::vector<uint8_t> proof; Check(EncodeQuietProofEnvelope(*result.proof,&proof),"existing native envelope encoding");
          std::ofstream output(argv[4],std::ios::binary); output.write(reinterpret_cast<const char*>(proof.data()),proof.size());
          Check(bool(output),"public interoperability artifact written");
        }
      } else if (scenario == "generation-failure" || scenario == "expires-proof" || scenario == "generation-exception") {
        Check(result.status == WalletSessionStatus::Failed && !result.proof,"failed/expired proof discarded");
      } else {
        Check(result.status == WalletSessionStatus::Canceled && !result.proof,"canceled proof discarded at safe boundary");
        Check(generated == ((scenario == "cancel-before" || scenario == "cancel-after-validation" || scenario == "cancel-unlock" || scenario == "cancel-prove-entry") ? 0 : 1),"cancellation uses actual safe boundary");
      }
      Check(result.cleanup == ((scenario == "cancel-before" || scenario == "cancel-unlock") ? WalletCleanup::NotNeeded : WalletCleanup::Relocked),"cleanup before proof independent of cancellation");
    }
    std::cout << "Proof session: " << checks << " checks passed; held=0 in-flight=0" << std::endl;
    return 0;
  } catch (const std::exception&) { std::cerr << "Proof session assertion failed; private diagnostics suppressed\n"; return 1; }
}
