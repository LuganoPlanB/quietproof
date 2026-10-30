#include "request.h"
#include "request_review.h"
#include "quietproof/chain_state.h"

#include "cli/json.hpp"
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace quietproof::gui;
namespace {
int checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}
proofs::QuietProofStatementV1 Fixture(int version) {
  proofs::QuietProofStatementV1 statement;
  statement.statement_version = version;
  statement.network = proofs::QuietProofNetwork::kRegtest;
  statement.verifier = "verifier.example";
  statement.purpose = "proof-of-funds";
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 2;
  statement.not_before = 1700000000;
  statement.expires_at = 2000000000;
  statement.has_snapshot = true;
  statement.snapshot.fill(0xab);
  statement.snapshot_height = 843210;
  for (int i=0; i<2; ++i) {
    proofs::QuietProofClaimV1 claim;
    for (size_t j=0; j<claim.txid.size(); ++j) claim.txid[j]=static_cast<uint8_t>(j+i+1);
    claim.vout = i+2;
    claim.amount_sats = i==0 ? 123456789 : 200000001;
    claim.program.fill(0x47);
    if (version==2 && i==1) claim.script_kind=proofs::QuietProofScriptKind::kP2pkh;
    statement.claims.push_back(claim);
  }
  return statement;
}
void Write(const fs::path& path, const proofs::QuietProofStatementV1& statement) {
  std::vector<uint8_t> bytes;
  Check(proofs::EncodeQuietProofStatement(statement,&bytes),"encode review fixture");
  std::ofstream file(path,std::ios::binary);
  file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
  Check(bool(file),"write review fixture");
}
nlohmann::json InspectJson(const RequestReview& review) {
  return {{"format",review.format},{"statement_version",review.statement_version},
      {"network",review.network},{"verifier",review.verifier},{"purpose",review.purpose},
      {"not_before",review.not_before},{"request_created_at",review.request_created_at},
      {"proof_created_at",review.proof_created_at ? nlohmann::json(*review.proof_created_at) : nlohmann::json(nullptr)},
      {"expires_at",review.expires_at},{"claims",review.claim_count},
      {"has_snapshot",review.has_snapshot},{"script_kinds",review.script_kinds}};
}
std::vector<uint8_t> Unhex(const std::string& text) {
  std::vector<uint8_t> bytes;
  for (size_t i=0; i<text.size(); i+=2) bytes.push_back(static_cast<uint8_t>(std::stoul(text.substr(i,2),nullptr,16)));
  return bytes;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc==4 && std::string(argv[1])=="--inspect") {
      RequestState state;
      state.Open(fs::path(argv[2]));
      if (!state.loaded) throw std::runtime_error(state.Message());
      const auto review=InspectRequest(state.loaded->statement);
      const auto now=std::stoll(argv[3]);
      std::cout << nlohmann::json{{"inspect",InspectJson(review)},
          {"window",RequestWindowName(RequestWindowAt(state.loaded->statement,now))},
          {"expires_utc",RequestUtcTime(review.expires_at)},
          {"verifier_display",RequestDisplayText(review.verifier)}}.dump() << '\n';
      return 0;
    }
    if (argc!=2) return 1;
    const fs::path directory(argv[1]);
    fs::create_directories(directory);
    for (int version : {1,2}) {
      const auto statement=Fixture(version);
      const auto review=InspectRequest(statement);
      Check(review.statement_version==version && review.network=="regtest" && review.claim_count==2,
            "native version/network/count presentation");
      Check(review.request_created_at==statement.not_before && review.not_before==statement.not_before &&
            review.expires_at==statement.expires_at && !review.proof_created_at,"request timestamp semantics");
      Check(review.total_sats==323456790 && review.has_snapshot && review.snapshot_height==843210 &&
            review.snapshot=="abababababababababababababababababababababababababababababababab",
            "snapshot and exact total amount");
      for (size_t i=0; i<review.claims.size(); ++i) {
        const auto& claim=review.claims[i];
        Check(claim.txid.size()==64 && Unhex(claim.txid)==std::vector<uint8_t>(statement.claims[i].txid.begin(),statement.claims[i].txid.end()) &&
              claim.vout==statement.claims[i].vout && claim.amount_sats==statement.claims[i].amount_sats,
              "outpoint display preserves RPC byte order and exact amount");
        Check(proofs::QuietProofMatchesScript(statement.claims[i],Unhex(claim.script_hex)),
              "displayed canonical script matches native classifier");
        Check(claim.script_kind==proofs::QuietProofScriptKindName(statement.claims[i].script_kind) &&
              review.script_kinds[i]==claim.script_kind,"per-claim script kind order");
      }
      Write(directory / ("review-v"+std::to_string(version)+".qpr"),statement);
    }
    auto statement=Fixture(2);
    statement.not_before=100;
    statement.expires_at=200;
    for (const auto [now,expected] : std::vector<std::pair<int64_t,RequestWindow>>{
        {-1,RequestWindow::ClockUnavailable},{99,RequestWindow::NotYetValid},
        {100,RequestWindow::Valid},{199,RequestWindow::Valid},{200,RequestWindow::Expired},{201,RequestWindow::Expired}}) {
      Check(RequestWindowAt(statement,now)==expected,"prover time boundary: inclusive start/exclusive expiry");
    }
    Write(directory / "boundaries.qpr",statement);
    statement.claims.clear();
    Check(RequestWindowAt(statement,150)==RequestWindow::Invalid,"invalid statements cannot be time-ready");
    Check(RequestUtcTime(0)=="1970-01-01 00:00:00 UTC","UTC epoch");
    Check(RequestUtcTime(1700000000)=="2023-11-14 22:13:20 UTC","UTC independent of local timezone");
    Check(RequestUtcTime(253402300799ULL)=="9999-12-31 23:59:59 UTC","maximum calendar timestamp");
    Check(RequestUtcTime(std::numeric_limits<uint64_t>::max()).find("18446744073709551615")!=std::string::npos,
          "huge wire timestamp displayed without overflow");
    Check(RequestAmount(1)=="0.00000001 BTC (1 sats)" && RequestAmount(100000000)=="1.00000000 BTC (100000000 sats)",
          "integer-only satoshi formatting");
    const std::string literal="https://example.org/##Display?x=%n&quoted=\"yes\"";
    Check(RequestDisplayText(literal)==literal,"URL/format/widget-looking strings remain literal");
    Check(RequestDisplayText("a\xe2\x80\xae" "b\xe2\x81\xa6")=="a[U+202E]b[U+2066]","directional controls displayed explicitly");
    Check(RequestDisplayText("Prüfung 東京")=="Prüfung 東京","valid Unicode bytes preserved for display");
    for (const auto network : {proofs::QuietProofNetwork::kMainnet,proofs::QuietProofNetwork::kTestnet3,
                              proofs::QuietProofNetwork::kTestnet4,proofs::QuietProofNetwork::kSignet}) {
      statement=Fixture(2);
      statement.network=network;
      statement.has_snapshot=false;
      statement.snapshot={};
      statement.snapshot_height=0;
      Write(directory / (std::string(proofs::QuietProofNetworkName(network))+".qpr"),statement);
    }
    statement=Fixture(2);
    statement.verifier=literal+std::string(256-literal.size(),'W');
    Write(directory / "long.qpr",statement);
    statement.verifier="example.org/\xe2\x80\xae" "##Display";
    Write(directory / "directional.qpr",statement);
    statement=Fixture(2);
    statement.purpose="bridge-authorization";
    statement.has_bridge_binding=true;
    statement.bridge.destination_network=proofs::QuietProofNetwork::kTestnet4;
    statement.bridge.destination_commitment[0]=1;
    statement.bridge.lock_id[0]=2;
    statement.bridge.asset_id="asset.example/##Display";
    Write(directory / "bridge.qpr",statement);
    statement=Fixture(2);
    statement.not_before=std::numeric_limits<uint64_t>::max()-1;
    statement.expires_at=std::numeric_limits<uint64_t>::max();
    Check(RequestWindowAt(statement,std::numeric_limits<int64_t>::max())==RequestWindow::NotYetValid,
          "future uint64 time is not narrowed into signed range");
    Write(directory / "huge-time.qpr",statement);
    statement=Fixture(2);
    const auto first=statement.claims.front();
    statement.claims.assign(16,first);
    for (size_t i=0; i<statement.claims.size(); ++i) {
      statement.claims[i].txid[0]=static_cast<uint8_t>(i+1);
      statement.claims[i].vout=static_cast<uint32_t>(i);
    }
    Write(directory / "many.qpr",statement);
    std::cout << "GUI review model: " << checks << " checks passed; fixtures=" << directory << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
