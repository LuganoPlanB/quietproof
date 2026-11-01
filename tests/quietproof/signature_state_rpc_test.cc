// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <iostream>
#include <stdexcept>
#include "bitcoin_rpc_json.h"
#include "quietproof/signature_verifier.h"

namespace {
using namespace proofs;
using namespace proofs::bitcoin_rpc_internal;
using Status = QuietProofNodeStateStatus;
size_t checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}
const std::string block(64, '1');
std::vector<std::string> replies;
std::vector<nlohmann::json> requests;
size_t fail_at = 99;
bool Transport(const BitcoinCoreRpcConfig&, const std::string& bytes, bool scan,
               HttpResponse* response, BitcoinRpcError* error, const std::optional<std::string>& wallet) {
  Check(!scan && !wallet, "state lookup used scan or wallet authority");
  const auto request = nlohmann::json::parse(bytes);
  const auto index = requests.size();
  requests.push_back(request);
  if (index == fail_at) {
    *error = {BitcoinRpcErrorCode::kTimeout, 0, std::nullopt, "redacted timeout"};
    return false;
  }
  Check(index < replies.size(), "extra state RPC");
  response->status = 200;
  response->body = "{\"jsonrpc\":\"2.0\",\"id\":" + request.at("id").dump() + ",\"result\":" + replies[index] + "}";
  return true;
}
nlohmann::json Tip() {
  return {{"chain", "regtest"}, {"blocks", 200}, {"bestblockhash", block},
          {"time", 10000}, {"initialblockdownload", false}};
}
nlohmann::json States(bool validated = true) {
  return {{"chainstates", nlohmann::json::array({{{"blocks", 200}, {"bestblockhash", block}, {"validated", validated}}})}};
}
BitcoinCoreRpcConfig Config() {
  BitcoinCoreRpcConfig config{QuietProofNetwork::kRegtest};
  config.rpc_datadir = "/unused-state-test";
  return config;
}
void Reset() { replies = {Tip().dump(), States().dump(), Tip().dump()}; requests.clear(); fail_at = 99; }
QuietProofNodeState Observe(Status status, size_t calls) {
  RpcClient client(Config(), Transport);
  const auto state = ObserveCurrentNodeState(client);
  Check(state.status == status && requests.size() == calls, "node-state classification/RPC count");
  for (size_t i = 0; i < calls; ++i)
    Check(requests[i].at("method") == (i == 1 ? "getchainstates" : "getblockchaininfo") &&
          requests[i].at("params") == nlohmann::json::array(), "node-state RPC method/params");
  return state;
}
void Run() {
  Reset();
  auto state = Observe(Status::kObserved, 3);
  Check(state.network == QuietProofNetwork::kRegtest && state.block[0] == 0x11 && state.height == 200 &&
        state.tip_time == 10000 && !state.initial_block_download && state.active_chainstate_validated, "observed node fields");
  for (bool validated : {false, true}) {
    Reset(); auto states = States(validated);
    const nlohmann::json background = {{"blocks", 100}, {"bestblockhash", std::string(64, '2')}, {"validated", !validated}};
    states["chainstates"].insert(states["chainstates"].begin(), background);
    replies[1] = states.dump();
    Check(Observe(Status::kObserved, 3).active_chainstate_validated == validated,
          "validated background entry replaced last active entry");
  }
  for (const auto& patch : {nlohmann::json{{"blocks", 201}}, nlohmann::json{{"bestblockhash", std::string(64, '2')}}}) {
    Reset(); auto states = States(); states["chainstates"].back().update(patch); replies[1] = states.dump();
    Observe(Status::kChanged, 2);
  }
  for (const auto& value : {nlohmann::json(nullptr), nlohmann::json(1), nlohmann::json("true")}) {
    Reset(); auto states = States(); states["chainstates"].back()["validated"] = value; replies[1] = states.dump();
    Observe(Status::kMalformed, 2);
  }
  for (const auto& field : {"blocks", "bestblockhash", "validated"}) {
    Reset(); auto states = States(); states["chainstates"].back().erase(field); replies[1] = states.dump();
    Observe(Status::kMalformed, 2);
  }
  for (const auto& states : {nlohmann::json::object(), nlohmann::json{{"chainstates", nullptr}},
                            nlohmann::json{{"chainstates", nlohmann::json::array()}},
                            nlohmann::json{{"chainstates", nlohmann::json::array({1, 2, 3})}}}) {
    Reset(); replies[1] = states.dump(); Observe(Status::kMalformed, 2);
  }
  for (const auto& patch : {nlohmann::json{{"time", -1}}, nlohmann::json{{"time", 1.5}},
                           nlohmann::json{{"time", "10000"}}, nlohmann::json{{"time", 0}},
                           nlohmann::json{{"initialblockdownload", 0}}, nlohmann::json{{"initialblockdownload", nullptr}}}) {
    Reset(); auto tip = Tip(); tip.update(patch); replies[0] = tip.dump(); Observe(Status::kMalformed, 2);
  }
  for (const auto& field : {"time", "initialblockdownload"}) {
    Reset(); auto tip = Tip(); tip.erase(field); replies[0] = tip.dump(); Observe(Status::kMalformed, 2);
  }
  for (size_t index = 0; index < 3; ++index) { Reset(); fail_at = index; Observe(Status::kUnavailable, index + 1); }
  Reset(); auto tip = Tip(); tip["chain"] = "main"; replies[0] = tip.dump(); Observe(Status::kWrongNetwork, 2);
  Reset(); tip = Tip(); tip["bestblockhash"] = std::string(64, '2'); replies[2] = tip.dump(); Observe(Status::kChanged, 3);
  Reset(); tip = Tip(); tip["time"] = 10001; replies[2] = tip.dump(); Observe(Status::kChanged, 3);
  Reset(); tip = Tip(); tip["initialblockdownload"] = true; replies[2] = tip.dump();
  Check(Observe(Status::kObserved, 3).initial_block_download, "IBD changed to true but readiness lost it");

  QuietProofChainRequest request{QuietProofNetwork::kRegtest}; request.txid.fill(0x11); request.vout = 3;
  const auto txout = [](const std::string& amount, const std::string& coinbase = "") {
    return "{\"bestblock\":\"" + block + "\",\"confirmations\":99,\"value\":" + amount +
        ",\"scriptPubKey\":{\"hex\":\"0014" + std::string(40, 'a') + "\"}" +
        (coinbase.empty() ? "" : ",\"coinbase\":" + coinbase) + "}";
  };
  const auto lookup = [&](const std::string& output, QuietProofChainStatus wanted) {
    Reset(); replies[1] = output;
    RpcClient client(Config(), Transport);
    const auto evidence = LookupCurrentTip(client, request);
    Check(evidence.status == wanted && evidence.status != QuietProofChainStatus::kSpent, "null/money lookup classification");
    Check(requests.at(1).at("method") == "gettxout" &&
          requests.at(1).at("params") == nlohmann::json::array({std::string(64, '1'), 3, true}), "mempool/display outpoint policy");
    return evidence;
  };
  for (const auto& coinbase : {std::string(), std::string("true"), std::string("false"), std::string("1")}) {
    const auto evidence = lookup(txout("0.00000001", coinbase), QuietProofChainStatus::kUnspent);
    Check(evidence.amount_sats == 1 && evidence.coinbase_known == (coinbase == "true" || coinbase == "false") &&
          evidence.coinbase == (coinbase == "true"), "exact amount/optional coinbase metadata");
  }
  for (const auto& amount : {"21000000.00000001", "18446744073709551616", "-1", "1e-8", "0.000000001"})
    lookup(txout(amount), QuietProofChainStatus::kMalformed);
  // gettxout returns null for both missing outputs and mempool-known spends;
  // neither case may be invented as definitive spent or unspent evidence.
  lookup("null", QuietProofChainStatus::kInconclusive);
  lookup("null", QuietProofChainStatus::kInconclusive);
  std::cout << "signature state RPC checks=" << checks << " failed=0 skipped=0\n";
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc == 1) Run();
    else if (argc == 4 && std::string(argv[1]) == "--http") {
      auto config = Config(); config.rpc_datadir.clear(); config.rpc_url = argv[2]; config.rpc_cookie = argv[3];
      config.rpc_timeout = std::chrono::milliseconds(100);
      BitcoinCoreRpc rpc(config);
      const auto state = rpc.ObserveNodeState();
      QuietProofChainRequest request{QuietProofNetwork::kRegtest}; request.txid.fill(0x11); request.vout = 3;
      const auto evidence = rpc.Lookup(request);
      std::cout << nlohmann::json({{"node_status", static_cast<unsigned>(state.status)},
          {"validated", state.active_chainstate_validated}, {"ibd", state.initial_block_download},
          {"output_status", static_cast<unsigned>(evidence.status)}, {"amount_sats", evidence.amount_sats},
          {"coinbase_known", evidence.coinbase_known}, {"coinbase", evidence.coinbase}}).dump() << '\n';
    } else return 1;
    return 0;
  } catch (...) { std::cerr << "signature state RPC test failed\n"; return 1; }
}
