#include "node_probe.h"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace quietproof::gui;
using namespace proofs;
namespace {
int checks = 0;
void Check(bool condition, const char* label) {
  ++checks;
  if (!condition) throw std::runtime_error(label);
}
NodeProbeResult Wait(NodeProbeWorker& worker) {
  const auto until = std::chrono::steady_clock::now()+std::chrono::seconds(6);
  while (std::chrono::steady_clock::now() < until) {
    if (auto value = worker.Poll()) return std::move(*value);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  throw std::runtime_error("worker result deadline");
}
}
int main(int argc, char** argv) {
  try {
    Check(argc == 4,"arguments");
    const std::string scenario(argv[3]);
    NodeConfiguration config{BitcoinCoreRpcConfig(QuietProofNetwork::kRegtest),{},{}};
    config.rpc.rpc_url = argv[1];
    config.rpc.rpc_cookie = argv[2];
    config.rpc.rpc_timeout = std::chrono::milliseconds(scenario == "async" || scenario == "shutdown" ? 5000 : 150);
    config.rpc.connect_timeout = config.rpc.rpc_timeout;
    BitcoinRpcKeyMatch match;
    match.program.fill(0x11);
    match.script_kinds = {scenario == "p2pkh" ? QuietProofScriptKind::kP2pkh : QuietProofScriptKind::kP2wpkh};
    NodeProbeState state;
    NodeProbeJob job{state.revision,config,match,true,{}};
    if (scenario == "selected") job.selected_wallet = "second";
    if (scenario == "missing-selection") job.selected_wallet = "missing";
    if (scenario == "no-request") { job.has_request = false; job.match.reset(); }
    if (scenario == "unsupported-request") job.match.reset();
    if (scenario == "budget") job.budget = std::chrono::milliseconds(120);
    if (scenario == "invalid-budget") job.budget = std::chrono::milliseconds(60001);
    if (scenario == "success") {
      QuietProofStatementV1 statement;
      statement.claims.resize(2);
      statement.claims[0].program.fill(0x11);
      statement.claims[1].program.fill(0x11);
      statement.claims[1].script_kind = QuietProofScriptKind::kP2pkh;
      Check(MatchRequest(LoadedRequest{{},{},statement})->script_kinds.size() == 2,"mixed script same-key request");
      statement.claims[1].program.fill(0x22);
      Check(!MatchRequest(LoadedRequest{{},{},statement}),"distinct request keys unsupported");
      statement.claims.clear();
      Check(!MatchRequest(LoadedRequest{{},{},statement}),"empty request has no key match");
    }
    NodeProbeResult result;
    if (scenario == "shutdown") {
      {
        NodeProbeWorker worker;
        Check(worker.Start(job),"start closing worker");
        std::cout << "started" << std::endl;
        std::cin.get();
        std::cout << "closing" << std::endl;
      }
      std::cout << "joined" << std::endl;
    } else {
      NodeProbeWorker worker;
      Check(worker.Start(job),"start worker");
      if (scenario == "async") {
        std::cout << "started" << std::endl;
        std::cin.get();  // Fixture asserts the HTTP operation is held first.
        Check(!worker.Start(job),"repeated start rejected while held");
        state.Invalidate();  // Represents settings/request/wallet replacement.
        std::cout << "held-rejection" << std::endl;
        std::cin.get();
      }
      result = Wait(worker);
      if (scenario == "async") {
        Check(!state.Accept(std::move(result)) && !state.result,"stale result discarded");
      } else {
        Check(state.Accept(std::move(result)) && state.result.has_value(),"current result accepted");
        const auto& value = *state.result;
        if (scenario == "unauthorized") Check(!value.probe.authenticated && value.error.code == BitcoinRpcErrorCode::kAuthentication,"authentication separate");
        else if (scenario == "invalid-budget") Check(!value.probe.authenticated && value.error.code == BitcoinRpcErrorCode::kConfiguration,"invalid budget rejected before RPC");
        else if (scenario == "refused") Check(value.error.code == BitcoinRpcErrorCode::kConnection,"connection refused");
        else if (scenario == "timeout" || scenario == "budget") Check(value.error.code == BitcoinRpcErrorCode::kTimeout,"bounded timeout");
        else if (scenario.starts_with("malformed") || scenario == "many-wallets") Check(value.probe.authenticated && value.error.code == BitcoinRpcErrorCode::kMalformed,"malformed response");
        else if (scenario == "wrong-script") Check(value.error.code == BitcoinRpcErrorCode::kInvalidAddress && !value.selected_wallet,"script mismatch");
        else {
          Check(value.complete && value.probe.authenticated && value.probe.version == 310100,"node version/auth");
          Check(value.probe.wallets_listed,"loaded wallet list");
          if (scenario == "wrong-chain") Check(value.probe.network_matches == false && !value.selected_wallet,"wrong chain blocks selection");
          else if (scenario == "syncing") Check(value.probe.syncing == true && value.Message().find("syncing") != std::string::npos,"sync separate");
          else if (scenario == "unsupported" || scenario == "unsupported-rpc") Check(value.probe.export_address_key == false && !value.selected_wallet && value.Message().find("Core") != std::string::npos,"Core unsupported proving");
          else if (scenario == "multiple" || scenario == "watch-only" || scenario == "not-mine" || scenario == "disabled-keys" || scenario == "unsupported-request" || scenario == "missing-selection" || scenario == "no-wallets" || scenario == "wallet-script-mismatch" || scenario == "legacy-wallet" || scenario == "external-signer")
            Check(!value.selected_wallet,"ambiguous/ineligible wallet not selected");
          else if (scenario == "selected") Check(value.selected_wallet == "second","explicit selection honored");
          else if (scenario == "empty-wallet") Check(value.selected_wallet == "","unnamed wallet selected");
          else Check(value.selected_wallet == "primary","sole eligible wallet selected");
          if (scenario != "wrong-chain") Check(value.probe.network_matches == true,"network match");
        }
        Check(value.error.message.find("synthetic-cookie") == std::string::npos &&
              value.error.message.find("server-private-diagnostic") == std::string::npos,"redacted errors");
      }
    }
    std::cout << "Node probe: " << checks << " checks passed" << std::endl;
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << std::endl;
    return 1;
  }
}
