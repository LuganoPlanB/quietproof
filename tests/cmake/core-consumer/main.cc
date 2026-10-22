#include "quietproof/challenge.h"
#include "quietproof/bitcoin_core.h"
int main() {
  using namespace proofs;
  proofs::QuietProofChallengeOptions options;
  if (static_cast<unsigned>(options.network) != 0xff) return 1;
  options.network = QuietProofNetwork::kRegtest;
  options.verifier = "installed-consumer";
  options.purpose = "proof-of-funds";
  QuietProofClaimV1 first;
  first.txid[0] = 1;
  first.amount_sats = 7;
  first.program[0] = 1;
  QuietProofStatementV1 statement;
  if (!CreateQuietProofChallenge({first}, options, &statement) ||
      statement.statement_version != 1) return 2;
  auto second = first;
  second.txid[0] = 2;
  second.amount_sats = 11;
  first.script_kind = QuietProofScriptKind::kP2pkh;
  if (!CreateQuietProofChallenge({first, second}, options, &statement) ||
      statement.statement_version != 2) return 3;
  std::vector<uint8_t> wire;
  QuietProofStatementV1 decoded;
  std::vector<std::array<uint8_t, 20>> hashes;
  if (!EncodeQuietProofStatement(statement, &wire) ||
      !DecodeQuietProofStatement(wire, &decoded) ||
      decoded.statement_version != 2 || decoded.claims.size() != 2 ||
      !QuietProofDistinctPrograms(decoded, &hashes) || hashes.size() != 1) return 4;
  std::vector<uint8_t> script{0x76, 0xa9, 0x14};
  script.insert(script.end(), first.program.begin(), first.program.end());
  script.insert(script.end(), {0x88, 0xac});
  if (!QuietProofMatchesScript(first, script) ||
      QuietProofMatchesScript(second, script)) return 5;
  script.push_back(0);
  return QuietProofMatchesScript(first, script) ? 6 : 0;
}
