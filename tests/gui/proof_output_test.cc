#include "proof_output.h"
#include "node_probe.h"
#include "wallet_session.h"
#include "private_input.h"
#include "shell.h"

#include <condition_variable>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace quietproof::gui;
using namespace proofs;
namespace {
int checks=0, scenarios=0;
void Check(bool value,const char* label) { ++checks; if(!value) throw std::runtime_error(label); }
std::vector<uint8_t> Read(const std::filesystem::path& p) { std::ifstream f(p,std::ios::binary); return {std::istreambuf_iterator<char>(f),{}}; }
void Write(const std::filesystem::path& p,std::string_view text) { std::ofstream f(p,std::ios::binary); f<<text; Check(bool(f),"write public sentinel"); }
void NoTemporary(const std::filesystem::path& p) { for(const auto& e:std::filesystem::directory_iterator(p)) Check(!e.path().filename().string().starts_with(".quietproof-"),"temporary output cleaned"); }
struct Gate {
  std::mutex mutex; std::condition_variable changed; bool entered=false,released=false; int active=0;
  void Hold() { std::unique_lock lock(mutex); entered=true; ++active; changed.notify_all(); const bool ok=changed.wait_for(lock,std::chrono::seconds(8),[&]{return released;}); --active; Check(ok,"held save released before wait deadline"); }
  void Entered() { std::unique_lock lock(mutex); Check(changed.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}),"save hold entered before invalidation"); }
  void Release() { std::lock_guard lock(mutex); released=true; changed.notify_all(); }
};
}
int main(int argc,char** argv) {
  std::filesystem::path scratch;
  try {
    Check(argc>=3,"arguments"); const auto public_wire=Read(argv[1]);
    QuietProofEnvelopeV1 envelope; Check(DecodeQuietProofEnvelope(public_wire,&envelope),"decode generated public proof");
    std::vector<uint8_t> request_wire; Check(EncodeQuietProofStatement(envelope.statement,&request_wire),"encode exact reviewed request");
    auto request=std::make_shared<const LoadedRequest>(LoadedRequest{{},request_wire,envelope.statement});
    if(argc==4 && std::string(argv[3])=="--prepare-request") {
      std::ofstream f(argv[2],std::ios::binary); f.write(reinterpret_cast<const char*>(request_wire.data()),request_wire.size()); Check(bool(f),"public request written"); return 0;
    }
    const bool fast=argc==4 && std::string(argv[3])=="--fast";
    const ProofVerifier verifier=fast ? ProofVerifier{[](const auto&){return true;}} : ProofVerifier{};
    const auto validation=ProofValidation::Run(request,envelope,[]{return false;},verifier);
    Check(bool(validation.proof) && validation.proof->Bytes()==public_wire,"real generated proof verifies and encodes existing bytes"); ++scenarios;
    auto proof=validation.proof;
    std::vector<std::function<void(QuietProofStatementV1&)>> mutations={
      [](auto& s){s.verifier+=".other";},[](auto& s){s.purpose+=".other";},[](auto& s){s.nonce[0]^=1;},
      [](auto& s){s.bip322_message_hash[0]^=1;},[](auto& s){--s.not_before;},[](auto& s){++s.expires_at;},
      [](auto& s){s.network=QuietProofNetwork::kMainnet;},[](auto& s){++s.claims[0].amount_sats;},
      [](auto& s){s.claims[0].txid[0]^=1;},[](auto& s){++s.claims[0].vout;},
      [](auto& s){s.claims[0].program[0]^=1;},[](auto& s){s.statement_version=2;s.claims[0].script_kind=QuietProofScriptKind::kP2pkh;}};
    for(const auto& mutate:mutations) {
      auto changed=envelope; mutate(changed.statement); int crypto_calls=0;
      auto value=ProofValidation::Run(request,changed,[]{return false;},[&](const auto&){++crypto_calls;return true;});
      Check(!value.proof && crypto_calls==0,"full statement mismatch rejected before crypto callback"); ++scenarios;
    }
    auto corrupt=envelope; corrupt.proof.bytes.back()^=128;
    Check(!ProofValidation::Run(request,corrupt,[]{return false;},fast ? ProofVerifier{[](const auto&){return false;}} : ProofVerifier{}).proof,"corrupt proof rejected"); ++scenarios;
    auto bad_bytes=request_wire; bad_bytes.back()^=1;
    Check(!ProofValidation::Run(std::make_shared<const LoadedRequest>(LoadedRequest{{},bad_bytes,envelope.statement}),envelope,[]{return false;},verifier).proof,"reviewed wire/decoded disagreement rejected"); ++scenarios;
    Check(!ProofValidation::Run(request,envelope,[]{return true;},verifier).proof,"validation cancels before native work"); ++scenarios;
    bool cancel_validation=false;
    Check(!ProofValidation::Run(request,envelope,[&]{return cancel_validation;},[&](const auto&){cancel_validation=true;return true;}).proof,"canceled validation result discarded after native boundary"); ++scenarios;
    auto unencodable=envelope; unencodable.proof.bytes.clear();
    Check(!ProofValidation::Run(request,unencodable,[]{return false;},[](const auto&){return true;}).proof,"incomplete encoded output cannot become sealed proof"); ++scenarios;
    const std::filesystem::path artifacts=argv[2]; std::filesystem::create_directories(artifacts);
    scratch=artifacts/("cases-"+std::to_string(getpid())); std::filesystem::create_directory(scratch);
    auto path=scratch/"output.qpf";
    auto job=[&](std::filesystem::path p,std::optional<OutputIdentity> replace=std::nullopt){return SaveJob{9,4,proof,std::move(p),replace};};
    auto save=RunSave(job(path),[]{return false;});
    Check(save.status==SaveStatus::Saved && save.committed && Read(path)==proof->Bytes(),"complete new output saved");
    struct stat mode{}; Check(stat(path.c_str(),&mode)==0 && (mode.st_mode&0777)==0600,"proof output owner-only permissions"); NoTemporary(scratch); ++scenarios;
    const std::string sentinel="previous public output";
    Write(path,sentinel); auto confirm=RunSave(job(path),[]{return false;});
    Check(confirm.status==SaveStatus::NeedsOverwrite && confirm.existing && Read(path)==std::vector<uint8_t>(sentinel.begin(),sentinel.end()),"overwrite requires explicit confirmation"); ++scenarios;
    const auto alias=scratch/"alias.qpf"; std::filesystem::create_hard_link(path,alias);
    confirm=RunSave(job(path),[]{return false;}); const auto token=*confirm.existing;
    Check(RunSave(job(alias,token),[]{return false;}).status==SaveStatus::DestinationChanged,"confirmation is bound to exact destination even for hard-link aliases"); ++scenarios;
    const auto other=scratch/"other.qpf"; Write(other,"different public output");
    Check(RunSave(job(other,token),[]{return false;}).status==SaveStatus::DestinationChanged,"confirmation cannot follow destination changes"); ++scenarios;
    save=RunSave(job(path,token),[]{return false;}); Check(save.committed && Read(path)==proof->Bytes(),"explicit exact-file overwrite succeeds"); ++scenarios;
    auto existing=[&] { Write(path,sentinel); auto r=RunSave(job(path),[]{return false;}); Check(bool(r.existing),"capture existing identity"); return *r.existing; };
    auto preserved=[&] { Check(Read(path)==std::vector<uint8_t>(sentinel.begin(),sentinel.end()),"previous output preserved"); NoTemporary(scratch); Check(proof==validation.proof,"verified proof retained without keys for retry"); };
    auto id=existing(); size_t written=0; SaveHooks disk;
    disk.write=[&](int fd,std::span<const uint8_t> bytes)->ptrdiff_t { if(written){errno=ENOSPC;return -1;} const auto n=write(fd,bytes.data(),bytes.size()); if(n>0)written+=n; return n; };
    save=RunSave(job(path,id),[]{return false;},disk); Check(save.status==SaveStatus::Failed && written>0 && !save.committed,"partial-write disk failure cannot publish"); preserved(); ++scenarios;
    id=existing(); SaveHooks sync; sync.sync=[](int){errno=EIO;return -1;};
    Check(RunSave(job(path,id),[]{return false;},sync).status==SaveStatus::Failed,"sync failure rejected before publication"); preserved(); ++scenarios;
    id=existing(); SaveHooks failure; failure.observe=[](auto point){if(point==SavePoint::Written)throw std::runtime_error("injected I/O failure");};
    Check(RunSave(job(path,id),[]{return false;},failure).status==SaveStatus::Failed,"exception cleans complete temporary before publication"); preserved(); ++scenarios;
    id=existing(); SaveHooks race; race.observe=[&](auto point){if(point==SavePoint::BeforeCommit)Write(path,"externally changed output");};
    Check(RunSave(job(path,id),[]{return false;},race).status==SaveStatus::DestinationChanged && Read(path)!=proof->Bytes(),"changed destination never silently replaced"); NoTemporary(scratch); ++scenarios;
    const auto appeared=scratch/"appeared.qpf"; race.observe=[&](auto point){if(point==SavePoint::BeforeCommit)Write(appeared,sentinel);};
    Check(RunSave(job(appeared),[]{return false;},race).status==SaveStatus::DestinationChanged && Read(appeared)==std::vector<uint8_t>(sentinel.begin(),sentinel.end()),"new destination race preserves competing output"); NoTemporary(scratch); ++scenarios;
    const auto link=scratch/"link.qpf"; std::filesystem::create_symlink(path,link);
    Check(RunSave(job(link),[]{return false;}).status==SaveStatus::Failed,"destination symlink refused"); ++scenarios;
    Check(RunSave(job(scratch),[]{return false;}).status==SaveStatus::Failed,"destination directory refused"); ++scenarios;
    const auto denied=scratch/"denied"; std::filesystem::create_directory(denied); chmod(denied.c_str(),0500);
    if(geteuid()!=0) Check(RunSave(job(denied/"proof.qpf"),[]{return false;}).status==SaveStatus::Failed,"real directory permission failure retains proof");
    else Check(RunSave(job("/proc/quietproof-test.qpf"),[]{return false;}).status==SaveStatus::Failed,"unwritable filesystem failure when root bypasses mode permissions");
    chmod(denied.c_str(),0700); ++scenarios;
    for(const auto point:{SavePoint::TemporaryCreated,SavePoint::Written,SavePoint::BeforeCommit,SavePoint::Committed}) {
      id=existing(); Gate gate; SaveHooks hooks; hooks.observe=[&](auto actual){if(actual==point)gate.Hold();};
      auto worker=std::make_unique<NodeProbeWorker>();
      try {
        Check(worker->StartSave(job(path,id),hooks),"save worker started"); gate.Entered();
        Check(!worker->StartSave(job(path,id)),"repeated save refused while held");
        NodeConfiguration config{BitcoinCoreRpcConfig(QuietProofNetwork::kRegtest),{},{}};
        Check(!worker->Start(NodeProbeJob{10,config,{},false,{}}),"node probe cannot overlap save");
        Check(!worker->StartWallet(WalletSessionJob{10,config,request,"primary",true},std::make_unique<PrivateInput>()),"key access cannot overlap save");
        worker->CancelWallet(); gate.Release(); // Release before join/poll on every path.
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(8);
        while(worker->Running() && std::chrono::steady_clock::now()<until) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        Check(!worker->Running(),"save worker settles after release"); auto value=worker->PollSave();
        Check(value && value->revision==9 && value->attempt==4 && !worker->PollSave(),"captured identity and exactly one save result");
        if(point==SavePoint::Committed) Check(value->status==SaveStatus::Saved && value->committed && Read(path)==proof->Bytes(),"late cancel preserves complete committed proof");
        else { Check(value->status==SaveStatus::Canceled && !value->committed,"precommit cancel publishes nothing"); preserved(); }
      } catch(...) { gate.Release(); worker->CancelWallet(); worker.reset(); throw; }
      gate.Release(); worker.reset(); Check(gate.active==0,"held/in-flight operations zero after worker join"); NoTemporary(scratch); ++scenarios;
    }
    id=existing(); Gate close_gate; SaveHooks close_hooks; close_hooks.observe=[&](auto p){if(p==SavePoint::BeforeCommit)close_gate.Hold();};
    auto closing=std::make_unique<NodeProbeWorker>();
    try { Check(closing->StartSave(job(path,id),close_hooks),"closing save started"); close_gate.Entered(); closing->CancelWallet(); close_gate.Release(); closing.reset(); }
    catch(...) { close_gate.Release(); if(closing)closing->CancelWallet(); closing.reset(); throw; }
    Check(close_gate.active==0,"close joined released save operation"); preserved(); ++scenarios;
    for(const bool close_validation:{false,true}) {
      Gate gate; auto validator=std::make_unique<NodeProbeWorker>();
      try {
        Check(validator->StartValidation(ValidationJob{23,request,argv[1]},[&](const auto&){gate.Hold();return true;}),"validation worker started");
        gate.Entered(); Check(!validator->StartSave(job(path,id)),"save cannot overlap held native validation boundary");
        validator->CancelWallet(); gate.Release();
        if(close_validation) validator.reset();
        else {
          const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(8);
          while(validator->Running() && std::chrono::steady_clock::now()<until)std::this_thread::sleep_for(std::chrono::milliseconds(1));
          Check(!validator->Running(),"invalidated validation settles after release");
          auto late=validator->PollWallet(); Check(late && late->revision==23 && late->status==WalletSessionStatus::Canceled && !late->verified && !late->key,"late validation cannot publish proof or secrets");
        }
      } catch(...) { gate.Release(); if(validator)validator->CancelWallet(); validator.reset(); throw; }
      gate.Release(); validator.reset(); Check(gate.active==0,"held validation released before close/join"); ++scenarios;
    }
    save=RunSave(job(path,id),[]{return false;}); Check(save.committed && Read(path)==proof->Bytes(),"retry succeeds using retained verified public proof"); ++scenarios;
    id=existing(); SaveHooks durability; durability.sync_directory=[](int){errno=EIO;return -1;};
    save=RunSave(job(path,id),[]{return false;},durability);
    Check(save.committed && save.status==SaveStatus::Saved && save.durability_warning && Read(path)==proof->Bytes(),"post-publication sync uncertainty reports complete output without deleting it"); NoTemporary(scratch); ++scenarios;
    {
      ShellState state; state.completed_proof=proof; state.node_probe.revision=9; state.save_attempt=4;
      state.save_dialog=true; state.AcceptSaveResult(confirm);
      Check(state.save_confirm && state.focus==308,"overwrite acceptance defaults to Cancel focus");
      state.InvalidateSaveDestination(); state.AcceptSaveResult(confirm);
      Check(!state.save_confirm && state.save_status.empty(),"late overwrite event cannot follow an edited destination");
      state.InvalidateNodeProbe(); state.completed_proof=proof;
      state.save_status="new context"; state.AcceptSaveResult(save);
      Check(state.completed_proof==proof && state.save_status=="new context" && state.save_notice.starts_with("Previous request"),"late committed output cannot replace current-context proof or status");
      ++scenarios;
    }
    auto final=RunSave(job(artifacts/"saved.qpf"),[]{return false;});
    if(final.status==SaveStatus::NeedsOverwrite)final=RunSave(job(artifacts/"saved.qpf",final.existing),[]{return false;});
    Check(final.committed && Read(artifacts/"saved.qpf")==public_wire,"interoperable artifact saved using GUI output API"); NoTemporary(scratch);
    std::filesystem::remove_all(scratch);
    std::cout<<"Proof output: "<<scenarios<<" scenarios, "<<checks<<" checks passed; native="<<!fast<<" held=0 in-flight=0\n";
    return 0;
  } catch(const std::exception& e) { if(!scratch.empty()){std::error_code ec;std::filesystem::remove_all(scratch,ec);} std::cerr<<"Proof output assertion: "<<e.what()<<'\n'; return 1; }
}
