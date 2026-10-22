// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "quietproof/bitcoin_core.h"
#include "quietproof/nonce_store.h"
#include "quietproof/verifier.h"

namespace proofs {
namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

QuietProofEnvelopeV1 Envelope() {
  QuietProofEnvelopeV1 envelope;
  auto& statement = envelope.statement;
  statement.network = QuietProofNetwork::kRegtest;
  statement.verifier = "verifier";
  statement.purpose = "proof-of-funds";
  statement.not_before = 1;
  statement.expires_at = 9;
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 2;
  QuietProofClaimV1 claim;
  claim.txid[0] = 3;
  claim.amount_sats = 7;
  claim.program[0] = 4;
  statement.claims = {claim};
  envelope.proof.circuit_digest[0] = 1;
  envelope.proof.bytes = {1};
  return envelope;
}

class FakeProvider final : public QuietProofChainProvider {
 public:
  QuietProofProviderKind kind() const override {
    return historical ? QuietProofProviderKind::kHistoricalSnapshot
                      : QuietProofProviderKind::kCurrentTip;
  }
  QuietProofChainEvidence Lookup(const QuietProofChainRequest& request) override {
    ++calls;
    last_request = request;
    auto result = request.vout < evidence_by_vout.size() ?
        evidence_by_vout[request.vout] : evidence;
    if (advance_block) result.block[0] = static_cast<uint8_t>(result.block[0] + calls);
    return result;
  }
  bool historical = false;
  int calls = 0;
  bool advance_block = false;
  QuietProofChainRequest last_request{};
  QuietProofChainEvidence evidence;
  std::vector<QuietProofChainEvidence> evidence_by_vout;
};

QuietProofVerifierConfig Config(FakeProvider* provider) {
  QuietProofVerifierConfig config;
  config.policy.now = 2;
  config.policy.verifier = "verifier";
  config.policy.purpose = "proof-of-funds";
  config.policy.consume_nonce = [](const std::array<uint8_t, 32>&) {
    return true;
  };
  config.verify_proof = [](const QuietProofEnvelopeV1&) { return true; };
  config.provider = provider;
  return config;
}

void SetMatchingEvidence(const QuietProofEnvelopeV1& envelope,
                         FakeProvider* provider) {
  provider->evidence.status = QuietProofChainStatus::kUnspent;
  provider->evidence.network = envelope.statement.network;
  provider->evidence.amount_sats = envelope.statement.claims[0].amount_sats;
  provider->evidence.confirmations = 2;
  provider->evidence.block[0] = 1;
  provider->evidence.height = 100;
  const auto& claim = envelope.statement.claims[0];
  auto& script = provider->evidence.script_pub_key;
  script = claim.script_kind == QuietProofScriptKind::kP2pkh ?
      std::vector<uint8_t>{0x76, 0xa9, 0x14} : std::vector<uint8_t>{0, 20};
  script.insert(script.end(), claim.program.begin(), claim.program.end());
  if (claim.script_kind == QuietProofScriptKind::kP2pkh)
    script.insert(script.end(), {0x88, 0xac});
}

void TestTypedChainEvidence() {
  for (const auto kind : {QuietProofScriptKind::kP2wpkh, QuietProofScriptKind::kP2pkh}) {
    auto envelope = Envelope();
    envelope.envelope_version = 2;
    envelope.proof_created_at = 2;
    envelope.statement.statement_version = 2;
    envelope.statement.claims[0].script_kind = kind;
    FakeProvider provider;
    SetMatchingEvidence(envelope, &provider);
    const auto valid = provider.evidence;
    int proofs = 0, consumed = 0;
    auto config = Config(&provider);
    config.verify_proof = [&](const auto&) { ++proofs; return true; };
    config.policy.consume_nonce = [&](const auto&) { ++consumed; return true; };
    std::vector<uint8_t> wire;
    Require(EncodeQuietProofEnvelope(envelope, &wire), "typed evidence fixture");
    auto result = VerifyQuietProof(wire, config);
    Require(result.result == QuietProofVerifyResult::kValidCurrent &&
                result.total_sats == 7 && proofs == 1 && consumed == 1,
            "typed evidence rejected");
    auto reject = [&](const QuietProofChainEvidence& evidence) {
      provider.evidence = evidence;
      const int proofs_before = proofs, consumed_before = consumed;
      Require(VerifyQuietProof(wire, config).result ==
                  QuietProofVerifyResult::kStateInconclusive &&
                  proofs == proofs_before + 1 && consumed == consumed_before,
              "bad evidence accepted, proof ordering changed, or nonce consumed");
    };
    auto bad = valid;
    ++bad.amount_sats;
    reject(bad);
    bad = valid;
    bad.network = QuietProofNetwork::kMainnet;
    reject(bad);
    bad = valid;
    bad.script_pub_key[kind == QuietProofScriptKind::kP2pkh ? 3 : 2] ^= 1;
    reject(bad);
    bad = valid;
    bad.script_pub_key.push_back(0);
    reject(bad);
    auto other_kind = envelope;
    other_kind.statement.claims[0].script_kind = kind == QuietProofScriptKind::kP2pkh ?
        QuietProofScriptKind::kP2wpkh : QuietProofScriptKind::kP2pkh;
    SetMatchingEvidence(other_kind, &provider);
    reject(provider.evidence);  // Identical hash with the wrong script kind.
    if (kind == QuietProofScriptKind::kP2wpkh) {
      // Legacy requests cannot authorize the P2PKH relation either.
      envelope.statement.statement_version = 1;
      Require(EncodeQuietProofEnvelope(envelope, &wire), "legacy typed test fixture");
      reject(provider.evidence);
    }
  }

  auto mixed = Envelope();
  mixed.envelope_version = 2;
  mixed.proof_created_at = 2;
  mixed.statement.statement_version = 2;
  FakeProvider provider;
  SetMatchingEvidence(mixed, &provider);
  provider.evidence_by_vout.push_back(provider.evidence);
  auto second = mixed.statement.claims[0];
  second.vout = 1;
  second.script_kind = QuietProofScriptKind::kP2pkh;
  mixed.statement.claims.push_back(second);
  auto p2pkh = mixed;
  p2pkh.statement.claims = {second};
  SetMatchingEvidence(p2pkh, &provider);
  provider.evidence_by_vout.push_back(provider.evidence);
  std::vector<std::array<uint8_t, 20>> key_hashes;
  Require(QuietProofDistinctPrograms(mixed.statement, &key_hashes) &&
              key_hashes.size() == 1 && key_hashes[0] == second.program,
          "same-key mixed scripts require extra ownership witness");
  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(mixed, &wire), "mixed evidence fixture");
  const auto result = VerifyQuietProof(wire, Config(&provider));
  Require(result.result == QuietProofVerifyResult::kValidCurrent &&
              result.total_sats == 14 && provider.calls == 2,
          "mixed same-key evidence rejected or wrong total");
  // Wire-level invalid claims reject before any expensive or stateful callback.
  std::vector<uint8_t> statement_bytes;
  Require(EncodeQuietProofStatement(mixed.statement, &statement_bytes), "mixed statement");
  int proofs = 0, consumed = 0;
  auto config = Config(&provider);
  config.verify_proof = [&](const auto&) { ++proofs; return true; };
  config.policy.consume_nonce = [&](const auto&) { ++consumed; return true; };
  auto invalid_wire = wire;
  const size_t second_vout = 9 + statement_bytes.size() - 65 + 32;
  std::fill_n(invalid_wire.begin() + second_vout, 4, 0);
  const int calls_before = provider.calls;
  Require(VerifyQuietProof(invalid_wire, config).result ==
              QuietProofVerifyResult::kMalformedStatement &&
              proofs == 0 && consumed == 0 && provider.calls == calls_before,
          "mixed duplicate reached callbacks");
  invalid_wire = wire;
  invalid_wire[9 + statement_bytes.size() - 65 + 44] = 2;
  Require(VerifyQuietProof(invalid_wire, config).result ==
              QuietProofVerifyResult::kUnsupported &&
              proofs == 0 && consumed == 0 && provider.calls == calls_before,
          "unknown kind reached callbacks");
  mixed.statement.claims[1].vout = 0;
  Require(!EncodeQuietProofEnvelope(mixed, &wire), "mixed duplicate encoded");
}

void TestVerifierStates() {
  auto envelope = Envelope();
  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "encode envelope");
  FakeProvider provider;
  SetMatchingEvidence(envelope, &provider);
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kValidCurrent,
          "current proof rejected");

  envelope.statement.has_snapshot = true;
  envelope.statement.snapshot[0] = 9;
  envelope.statement.snapshot_height = 123;
  provider.historical = true;
  provider.evidence.block = envelope.statement.snapshot;
  provider.evidence.height = envelope.statement.snapshot_height;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "encode snapshot envelope");
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kValidHistorical &&
              provider.last_request.snapshot_height == 123,
          "historical proof rejected or height not forwarded");
  provider.evidence.height = 124;
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kStateInconclusive,
          "historical provider substituted a different snapshot");
  provider.evidence.height = envelope.statement.snapshot_height;
  provider.historical = false;
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kStateInconclusive,
          "current provider accepted historical request");

  envelope.statement.has_snapshot = false;
  envelope.statement.snapshot.fill(0);
  envelope.statement.snapshot_height = 0;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "encode current envelope");
  provider.evidence.amount_sats = 8;
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kStateInconclusive,
          "amount substitution accepted");
  SetMatchingEvidence(envelope, &provider);
  provider.evidence.status = QuietProofChainStatus::kSpent;
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kSpentAtSnapshot,
          "spent output accepted");
  SetMatchingEvidence(envelope, &provider);
  auto config = Config(&provider);
  config.min_confirmations = 3;
  Require(VerifyQuietProof(wire, config).result ==
              QuietProofVerifyResult::kStaleSnapshot,
          "confirmation policy bypassed");
  config = Config(&provider);
  config.verify_proof = [](const QuietProofEnvelopeV1&) { return false; };
  const int calls_before = provider.calls;
  Require(VerifyQuietProof(wire, config).result ==
              QuietProofVerifyResult::kInvalidProof &&
              provider.calls == calls_before,
          "invalid proof reached chain provider");
  config = Config(&provider);
  config.supports = [](const QuietProofEnvelopeV1&) { return false; };
  Require(VerifyQuietProof(wire, config).result ==
              QuietProofVerifyResult::kUnsupported,
          "unknown circuit identity misclassified");
  auto multiple = envelope;
  auto second_claim = multiple.statement.claims[0];
  second_claim.txid[0] = 4;
  multiple.statement.claims.push_back(second_claim);
  Require(EncodeQuietProofEnvelope(multiple, &wire), "encode multi-claim envelope");
  SetMatchingEvidence(multiple, &provider);
  provider.calls = 0;
  provider.advance_block = true;
  Require(VerifyQuietProof(wire, Config(&provider)).result ==
              QuietProofVerifyResult::kStateInconclusive,
          "multi-claim verification mixed chain tips");
  provider.advance_block = false;
  int proof_calls = 0;
  config = Config(&provider);
  config.policy.now = envelope.statement.expires_at;
  config.verify_proof = [&](const QuietProofEnvelopeV1&) {
    ++proof_calls;
    return true;
  };
  Require(VerifyQuietProof(wire, config).result ==
              QuietProofVerifyResult::kInvalidProof &&
              proof_calls == 0,
          "expired request reached expensive proof verification");
}

std::string TipJson(const std::string& chain, char block_digit = 'a',
                    uint64_t height = 100) {
  return "{\"chain\":\"" + chain + "\",\"blocks\":" +
         std::to_string(height) + ",\"bestblockhash\":\"" +
         std::string(64, block_digit) + "\"}";
}

std::string TxoutJson(const std::string& amount = "0.00000007",
                      char block_digit = 'a') {
  return "{\"bestblock\":\"" + std::string(64, block_digit) +
         "\",\"confirmations\":2,\"value\":" + amount +
         ",\"scriptPubKey\":{\"hex\":"
         "\"00140400000000000000000000000000000000000000\"}}";
}

void TestProofTimestampPolicy() {
  auto envelope = Envelope();
  envelope.envelope_version = 2;
  envelope.proof_created_at = 3;
  FakeProvider provider;
  SetMatchingEvidence(envelope, &provider);
  auto config = Config(&provider);
  bool consumed = false;
  config.policy.consume_nonce = [&](const auto&) { consumed = true; return true; };
  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "timestamp fixture");
  Require(VerifyQuietProof(wire, config).result == QuietProofVerifyResult::kInvalidProof &&
              provider.calls == 0 && !consumed, "future timestamp accepted");
  config.policy.now = 3;
  Require(VerifyQuietProof(wire, config).result == QuietProofVerifyResult::kValidCurrent && consumed,
          "current timestamp rejected");
}

void TestBitcoinAmounts() {
  uint64_t sats = 0;
  Require(quietproof_internal::BitcoinAmountToSats("0.00000001", &sats) &&
              sats == 1,
          "one satoshi parse failed");
  Require(quietproof_internal::BitcoinAmountToSats("21000000.00000000", &sats) &&
              sats == kQuietProofMaxMoneySats,
          "maximum supply parse failed");
  Require(!quietproof_internal::BitcoinAmountToSats("0.000000001", &sats),
          "sub-satoshi amount accepted");
  Require(!quietproof_internal::BitcoinAmountToSats("21000000.00000001", &sats),
          "amount above maximum accepted");
  Require(!quietproof_internal::BitcoinAmountToSats("1e-8", &sats),
          "noncanonical exponent accepted");
  std::string token;
  Require(!quietproof_internal::TopLevelNumberToken(
              "{\"value\":1,\"value\":2}", "value", &token),
          "duplicate top-level amount accepted");
}

void TestCoreSharedFields() {
  quietproof_internal::Tip text_tip, fields_tip;
  const auto text = TipJson("signet");
  Require(quietproof_internal::ParseTip(text, &text_tip) &&
              quietproof_internal::ParseTipFields(nlohmann::json::parse(text),
                                                 &fields_tip) &&
              text_tip.chain == fields_tip.chain &&
              text_tip.best_block_hash == fields_tip.best_block_hash &&
              text_tip.height == fields_tip.height,
          "text and decoded tip validation differ");
  for (const auto& invalid : {std::string("null"), std::string("[]"),
                              std::string("{}"), std::string("{"),
                              TipJson("signet", 'A')}) {
    Require(!quietproof_internal::ParseTip(invalid, &fields_tip) &&
                fields_tip.chain == text_tip.chain &&
                fields_tip.best_block_hash == text_tip.best_block_hash &&
                fields_tip.height == text_tip.height,
            "bad tip accepted or output changed");
  }
  Require(!quietproof_internal::ParseTip(
              std::string(kQuietProofMaxRpcOutputBytes + 1, ' '), &fields_tip),
          "oversized tip accepted");
  uint64_t number = 0;
  Require(quietproof_internal::JsonUnsigned(nlohmann::json(uint64_t{42}), &number) &&
              number == 42 &&
              quietproof_internal::JsonUnsigned(nlohmann::json(int64_t{7}), &number) &&
              number == 7,
          "integer helper changed");
  for (const auto& invalid : {nlohmann::json(-1), nlohmann::json(1.0),
                              nlohmann::json("1"), nlohmann::json(true)}) {
    Require(!quietproof_internal::JsonUnsigned(invalid, &number),
            "non-unsigned field accepted");
  }
  std::vector<uint8_t> script;
  uint64_t amount = 0, confirmations = 0;
  // The original decimal token is independent of the DOM's double value.
  const auto txout = nlohmann::json::parse(TxoutJson("12345678.12345678"));
  Require(quietproof_internal::TxOutShapeValid(txout) &&
              quietproof_internal::ParseTxOutFields(
                  txout, "12345678.12345678", std::string(64, 'a'), &amount,
                  &confirmations, &script) &&
              amount == 1234567812345678ULL && confirmations == 2 &&
              script.size() == 22 && script[0] == 0 && script[1] == 0x14 &&
              script[2] == 4,
          "decoded txout fields changed");
  Require(!quietproof_internal::ParseTxOutFields(
              txout, "1e-8", std::string(64, 'a'), &amount, &confirmations,
              &script) &&
              !quietproof_internal::ParseTxOutFields(
                  txout, "0.1", std::string(64, 'b'), &amount, &confirmations,
                  &script) &&
              !quietproof_internal::TxOutShapeValid(nullptr),
          "noncanonical txout accepted");
}

void TestCoreFieldFailures() {
  QuietProofChainRequest request;
  request.network = QuietProofNetwork::kSignet;
  request.txid[0] = 3;
  struct Case {
    std::string response;
    QuietProofChainStatus status;
    const char* detail;
  };
  const Case cases[] = {
      {"{", QuietProofChainStatus::kMalformed, "gettxout returned invalid JSON"},
      {"[]", QuietProofChainStatus::kMalformed,
       "gettxout response has an unexpected shape"},
      {"{}", QuietProofChainStatus::kMalformed,
       "gettxout response has an unexpected shape"},
      {TxoutJson("0.00000007", 'b'), QuietProofChainStatus::kMalformed,
       "gettxout fields are not canonical"},
      {TxoutJson("1e-8"), QuietProofChainStatus::kMalformed,
       "gettxout fields are not canonical"},
      {TxoutJson("\"0.00000007\""), QuietProofChainStatus::kMalformed,
       "gettxout fields are not canonical"},
      {TxoutJson("21000000.00000001"), QuietProofChainStatus::kMalformed,
       "gettxout fields are not canonical"},
      {TxoutJson("-0.00000001"), QuietProofChainStatus::kMalformed,
       "gettxout fields are not canonical"},
  };
  for (const auto& test : cases) {
    int calls = 0;
    BitcoinCoreCurrentTipProvider provider(
        "/usr/bin/bitcoin-cli", request.network,
        [&](const std::vector<std::string>& arguments) {
          ++calls;
          return QuietProofProcessResult{
              0, arguments.back() == "getblockchaininfo" ? TipJson("signet")
                                                       : test.response,
              ""};
        });
    const auto evidence = provider.Lookup(request);
    Require(evidence.status == test.status && evidence.detail == test.detail &&
                calls == 2 && evidence.script_pub_key.empty() &&
                evidence.amount_sats == 0 && evidence.confirmations == 0,
            "legacy malformed-field classification changed");
  }
  for (const auto& field : {std::string("confirmations"), std::string("scriptPubKey")}) {
    auto response = nlohmann::json::parse(TxoutJson("1"));
    if (field == "confirmations") response[field] = -1;
    else response[field]["hex"] = "0014FF";
    const std::string malformed = response.dump();
    BitcoinCoreCurrentTipProvider provider(
        "/usr/bin/bitcoin-cli", request.network,
        [&](const std::vector<std::string>& arguments) {
          return QuietProofProcessResult{
              0, arguments.back() == "getblockchaininfo" ? TipJson("signet")
                                                       : malformed,
              ""};
        });
    Require(provider.Lookup(request).status == QuietProofChainStatus::kMalformed,
            "bad confirmations or hex accepted");
  }
}

void TestCoreNetworks() {
  struct NetworkCase { QuietProofNetwork network; const char* chain; const char* flag; };
  const NetworkCase networks[] = {
      {QuietProofNetwork::kMainnet, "main", ""},
      {QuietProofNetwork::kTestnet3, "test", "-testnet"},
      {QuietProofNetwork::kTestnet4, "testnet4", "-testnet4"},
      {QuietProofNetwork::kSignet, "signet", "-signet"},
      {QuietProofNetwork::kRegtest, "regtest", "-regtest"},
  };
  for (const auto& network : networks) {
    int calls = 0;
    BitcoinCoreCurrentTipProvider provider(
        "/usr/bin/bitcoin-cli", network.network,
        [&](const std::vector<std::string>& arguments) {
          ++calls;
          Require((network.flag[0] == '\0' && arguments.size() >= 2) ||
                      (arguments.size() >= 3 && arguments[1] == network.flag),
                  "Bitcoin Core network selector missing");
          if (arguments.back() == "getblockchaininfo")
            return QuietProofProcessResult{0, TipJson(network.chain), ""};
          return QuietProofProcessResult{0, TxoutJson(), ""};
        });
    QuietProofChainRequest request;
    request.network = network.network;
    request.txid[0] = 3;
    const auto evidence = provider.Lookup(request);
    std::array<uint8_t, 32> expected_block;
    expected_block.fill(0xaa);
    Require(evidence.status == QuietProofChainStatus::kUnspent &&
                evidence.network == network.network &&
                evidence.amount_sats == 7 && evidence.confirmations == 2 &&
                evidence.height == 100 && evidence.block == expected_block &&
                evidence.script_pub_key.size() == 22 &&
                evidence.script_pub_key[0] == 0 &&
                evidence.script_pub_key[1] == 0x14 &&
                evidence.script_pub_key[2] == 4 && calls == 3,
            "realistic gettxout response rejected");
  }
}

void TestCoreFailures() {
  QuietProofChainRequest request;
  request.network = QuietProofNetwork::kSignet;
  request.txid[0] = 3;
  BitcoinCoreCurrentTipProvider wrong_network(
      "/usr/bin/bitcoin-cli", QuietProofNetwork::kSignet,
      [](const std::vector<std::string>&) {
        return QuietProofProcessResult{0, TipJson("main"), ""};
      });
  Require(wrong_network.Lookup(request).status == QuietProofChainStatus::kWrongNetwork,
          "wrong Bitcoin Core network accepted");

  BitcoinCoreCurrentTipProvider missing(
      "/usr/bin/bitcoin-cli", QuietProofNetwork::kSignet,
      [](const std::vector<std::string>& arguments) {
        if (arguments.back() == "getblockchaininfo")
          return QuietProofProcessResult{0, TipJson("signet"), ""};
        return QuietProofProcessResult{0, "null\n", ""};
      });
  Require(missing.Lookup(request).status == QuietProofChainStatus::kInconclusive,
          "missing outpoint incorrectly asserted spent");

  int tip_calls = 0;
  BitcoinCoreCurrentTipProvider reorg(
      "/usr/bin/bitcoin-cli", QuietProofNetwork::kSignet,
      [&](const std::vector<std::string>& arguments) {
        if (arguments.back() == "getblockchaininfo") {
          ++tip_calls;
          return QuietProofProcessResult{
              0, TipJson("signet", tip_calls == 1 ? 'a' : 'b'), ""};
        }
        return QuietProofProcessResult{0, TxoutJson(), ""};
      });
  const auto raced = reorg.Lookup(request);
  Require(raced.status == QuietProofChainStatus::kInconclusive &&
              raced.detail == "chain tip changed during lookup" &&
              raced.script_pub_key.size() == 22 && raced.amount_sats == 0 &&
              raced.confirmations == 0 && raced.height == 0,
          "tip race accepted");
}

void TestProcessRunner() {
  const auto result = QuietProofRunArgv({"/bin/echo", "safe argument; no shell"});
  Require(result.exit_code == 0 &&
              result.stdout_text == "safe argument; no shell\n" &&
              result.stderr_text.empty(),
          "argv process runner failed");
  Require(QuietProofRunArgv({"echo", "relative"}).exit_code == -1,
          "relative executable accepted");
  Require(QuietProofRunArgv({"/bin/false"}).exit_code != 0,
          "child failure reported as success");
  const auto excessive = QuietProofRunArgv({"/usr/bin/yes", "bounded"});
  Require(excessive.output_limit_exceeded && excessive.exit_code == -1 &&
              excessive.stdout_text.size() == kQuietProofMaxRpcOutputBytes,
          "RPC output ceiling not enforced");
}

void TestNonceStore() {
  char path[] = "/tmp/quietproof-nonce-test.XXXXXX";
  const int descriptor = mkstemp(path);
  Require(descriptor >= 0 && fchmod(descriptor, 0600) == 0 &&
              close(descriptor) == 0,
          "nonce store fixture failed");
  std::array<uint8_t, 32> nonce{};
  nonce[0] = 1;
  Require(QuietProofConsumeNonceFile(path, nonce), "fresh nonce not stored");
  Require(!QuietProofConsumeNonceFile(path, nonce), "stored nonce replay accepted");
  std::array<uint8_t, 32> another{};
  another[0] = 2;
  Require(chmod(path, 0644) == 0 &&
              !QuietProofConsumeNonceFile(path, another),
          "insecure nonce-store permissions accepted");
  Require(unlink(path) == 0, "nonce store fixture cleanup failed");
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestTypedChainEvidence();
    proofs::TestVerifierStates();
    proofs::TestProofTimestampPolicy();
    proofs::TestBitcoinAmounts();
    proofs::TestCoreSharedFields();
    proofs::TestCoreFieldFailures();
    proofs::TestCoreNetworks();
    proofs::TestCoreFailures();
    proofs::TestProcessRunner();
    proofs::TestNonceStore();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "QuietProof integration tests passed\n";
  return 0;
}
