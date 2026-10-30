#include "wallet_session.h"
#include "private_input.h"

#include <atomic>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace quietproof::gui;
using namespace proofs;
namespace {
int checks = 0;
void Check(bool value, const char* label) {
  ++checks;
  if (!value) throw std::runtime_error(label);
}
QuietProofStatementV1 Statement() {
  QuietProofStatementV1 s;
  s.network = QuietProofNetwork::kRegtest;
  s.verifier = "session.example"; s.purpose = "proof-of-control";
  s.nonce[0] = 1; s.bip322_message_hash[0] = 2;
  s.not_before = 100; s.expires_at = 200;
  QuietProofClaimV1 claim;
  claim.txid[0] = 1; claim.amount_sats = 1;
  // Public compressed generator key's HASH160. Private fixture is generated
  // inside the mock server, never carried in command arguments or evidence.
  claim.program = {0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
                   0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6};
  s.claims.push_back(claim);
  return s;
}
}
int main(int argc, char** argv) {
  try {
    if (argc == 3 && (std::string(argv[1]) == "--write-request" || std::string(argv[1]) == "--write-replacement")) {
      auto statement = Statement(); statement.not_before = 1700000000; statement.expires_at = 2000000000;
      if (std::string(argv[1]) == "--write-replacement") statement.verifier = "replacement.example";
      std::vector<uint8_t> bytes; Check(EncodeQuietProofStatement(statement,&bytes),"encode public UI request");
      std::ofstream output(argv[2],std::ios::binary); output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
      Check(bool(output),"write public UI request"); return 0;
    }
    Check(argc == 4,"arguments");
    const std::string scenario(argv[3]);
    const bool controlled = scenario == "wallet-switch" || scenario == "request-switch" || scenario == "close" || scenario == "cancel-after-unlock" || scenario == "export-preflight-cancel";
    NodeConfiguration config{BitcoinCoreRpcConfig(QuietProofNetwork::kRegtest),{},{}};
    config.rpc.rpc_url = argv[1]; config.rpc.rpc_cookie = argv[2];
    config.rpc.rpc_timeout = std::chrono::milliseconds(150);
    if (controlled)
      config.rpc.rpc_timeout = std::chrono::milliseconds(3000);
    config.rpc.connect_timeout = config.rpc.rpc_timeout;
    auto statement = Statement();
    if (scenario.starts_with("worker-")) {
      statement.not_before = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()-100;
      statement.expires_at = statement.not_before+1000;
      config.rpc.rpc_timeout = std::chrono::milliseconds(3000);
    }
    if (scenario == "unsupported-script") statement.claims[0].script_kind = static_cast<QuietProofScriptKind>(255);
    if (scenario == "p2pkh") { statement.statement_version = 2; statement.claims[0].script_kind = QuietProofScriptKind::kP2pkh; }
    if (scenario == "expired") statement.expires_at = 150;
    WalletSessionJob job{7,config,std::make_shared<const LoadedRequest>(LoadedRequest{{},{},statement}),
                         scenario == "unnamed" ? "" : "primary",true};
    if (scenario == "no-approval") job.prove_approved = false;
    if (scenario == "no-selection") job.wallet.reset();
    if (scenario == "network-config") job.configuration.rpc.network = QuietProofNetwork::kMainnet;
    std::atomic<bool> canceled{scenario == "cancel-before"};
    int clocks = 0;
    auto clock = [&] { return scenario == "expires-after-probe" && ++clocks >= 2 ? 200 : 150; };
    // Dedicated local synthetic bytes, never printed or put in argv/env.
    std::array<char,12> password{};
    for (size_t i=0;i<password.size();++i) password[i] = static_cast<char>(65+i);
    std::atomic<bool> consumed{false};
    auto run = [&](std::span<const char> input) { return RunWalletSession(job,input,[&] { return canceled.load(); },clock,[&] {
      if (scenario == "export-preflight-cancel") { ErasePrivateMemory(password.data(),password.size()); consumed.store(true); }
    }); };
    WalletSessionResult result;
    if (scenario.starts_with("worker-")) {
      auto worker = std::make_unique<NodeProbeWorker>();
      auto input = [&] { auto value = std::make_unique<PrivateInput>(); Check(value->Append({password.data(),password.size()}),"worker input accepted"); return value; };
      Check(worker->StartWallet(job,input()),"wallet worker started");
      if (scenario == "worker-cancel" || scenario == "worker-close") {
        std::cout << "started" << std::endl; std::cin.get();
        Check(!worker->StartWallet(job,input()),"duplicate wallet work refused while held");
        Check(!worker->Start(NodeProbeJob{8,config,{},false,{}}),"probe cannot overlap held wallet");
        worker->CancelWallet();
        std::cout << "invalidated" << std::endl; std::cin.get();
      }
      auto wait = [&] {
        const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(6);
        while (std::chrono::steady_clock::now()<deadline) {
          if (auto value = worker->PollWallet()) return std::move(*value);
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("wallet worker result deadline");
      };
      if (scenario == "worker-close") {
        worker.reset(); Check(true,"closing worker joins captured-wallet cleanup");
      } else {
        result = wait();
        if (scenario == "worker-retry") {
          Check(result.error.code == BitcoinRpcErrorCode::kWrongPassphrase && !result.key,"worker wrong password redacted");
          Check(worker->StartWallet(job,input()),"explicit retry uses fresh owned input"); result = wait();
        }
        Check(!result.key,"key never crosses worker/UI queue");
        Check(result.wallet == job.wallet && result.revision == job.revision,"worker result preserves captured identity");
        Check(result.cleanup == WalletCleanup::Relocked,"worker relock observable");
        Check(result.status == (scenario == "worker-cancel" ? WalletSessionStatus::Canceled : WalletSessionStatus::Acquired),"worker result state exact");
      }
    } else if (scenario == "prompt" || scenario == "retry") {
      result = run({});
      if (scenario == "prompt") Check(result.status == WalletSessionStatus::PasswordRequired,"only locked wallet prompts");
      else {
        Check(result.status == WalletSessionStatus::PasswordRequired,"first password prompt");
        result = run(password);
        Check(result.error.code == BitcoinRpcErrorCode::kWrongPassphrase && !result.key,"first explicit password rejected");
        result = run(password);
        Check(result.status == WalletSessionStatus::Acquired,"explicit retry succeeds");
      }
    } else if (controlled) {
      std::thread worker([&] { result = run(password); });
      std::cout << "started" << std::endl;
      std::cin.get();
      if (scenario == "export-preflight-cancel")
        Check(consumed.load() && std::all_of(password.begin(),password.end(),[](char c) { return c == 0; }),"owned password erased before export preflight completes");
      canceled.store(true); // UI revision/selection replacement and close cancel.
      std::cout << "invalidated" << std::endl;
      std::cin.get();
      worker.join();
      Check(result.status == WalletSessionStatus::Canceled && !result.key,"in-flight cancellation discards key");
      Check(result.unlock_confirmed && result.cleanup == WalletCleanup::Relocked,"cancellation relocks captured wallet");
    } else result = run(password);
    if (scenario == "locked" || scenario == "unnamed" || scenario == "unlocked" || scenario == "unencrypted" || scenario == "became-unlocked" || scenario == "p2pkh") {
      Check(result.status == WalletSessionStatus::Acquired && bool(result.key),"valid request key acquired");
      Check(result.key->Bytes()[31] == 1,"synthetic key matches");
      const bool owned = scenario != "unlocked" && scenario != "unencrypted" && scenario != "became-unlocked";
      Check(result.unlock_attempted == owned && result.unlock_confirmed == owned,"unlock ownership exact");
      Check(result.cleanup == (owned ? WalletCleanup::Relocked : WalletCleanup::NotNeeded),"preexisting wallet state preserved");
    } else if (scenario == "wrong-password") {
      Check(result.error.code == BitcoinRpcErrorCode::kWrongPassphrase && !result.key,"password error distinct from RPC auth");
      Check(result.cleanup == WalletCleanup::NotNeeded,"definitive rejection grants no ownership");
    } else if (scenario == "relock-failure" || scenario == "lock-timeout" || scenario == "lock-malformed") {
      Check(result.cleanup == WalletCleanup::Failed && !result.key && result.status == WalletSessionStatus::Failed,"unconfirmed cleanup discards key");
      Check(result.Message().find("15-second") != std::string::npos,"timed fallback visible");
    } else if (scenario == "unlock-disconnect" || scenario == "unlock-timeout" || scenario == "unlock-malformed") {
      Check(result.unlock_attempted && !result.unlock_confirmed && result.cleanup == WalletCleanup::Relocked && !result.key,"uncertain unlock still relocks");
      Check(result.Message().find("late node processing") != std::string::npos,"uncertain processing race visible");
    } else if (scenario == "bad-key" || scenario == "out-of-range-key" || scenario == "wrong-key" || scenario == "malformed-export" || scenario == "uncompressed-export" || scenario == "unsupported-export" || scenario == "export-failure" || scenario == "export-disconnect" || scenario == "export-timeout" || scenario == "export-partial-timeout") {
      Check(result.status == WalletSessionStatus::Failed && !result.key && result.cleanup == WalletCleanup::Relocked,"failed export/key validation cleaned");
      if (scenario == "export-partial-timeout")
        Check(result.error.code == BitcoinRpcErrorCode::kTimeout && result.error.http_status == 200,"partial response timeout retained status without a secret result");
    } else if (!scenario.starts_with("worker-") && scenario != "prompt" && scenario != "retry" && !controlled) {
      Check(!result.key && result.status != WalletSessionStatus::Acquired,"rejected session cannot retain key");
    }
    if (scenario != "worker-close") Check(result.revision == 7,"request revision preserved");
    Check(result.Message().find(std::string(password.data(),password.size())) == std::string::npos &&
          result.error.message.find("server-private-diagnostic") == std::string::npos &&
          result.cleanup_error.message.find("server-private-diagnostic") == std::string::npos,"authored status is redacted");
    volatile char* p = password.data();
    for (size_t i=0;i<password.size();++i) p[i] = 0;
    std::cout << "Wallet session: " << checks << " checks passed" << std::endl;
    return 0;
  } catch (...) { std::cerr << "Wallet session assertion failed; private diagnostics suppressed" << std::endl; return 1; }
}
