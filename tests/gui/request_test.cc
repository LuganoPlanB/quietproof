#include "request.h"
#include "quietproof/envelope.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <type_traits>

namespace fs = std::filesystem;
using namespace quietproof::gui;
namespace {
int checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::vector<uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary);
  output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  if (!output) throw std::runtime_error("Cannot write test fixture");
}
proofs::QuietProofStatementV1 Statement(int version) {
  proofs::QuietProofStatementV1 statement;
  statement.statement_version = version;
  statement.network = proofs::QuietProofNetwork::kRegtest;
  statement.verifier = "example.org / request-provided";
  statement.purpose = "proof-of-control";
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 2;
  statement.not_before = 1;
  statement.expires_at = 4000000000;
  proofs::QuietProofClaimV1 claim;
  claim.txid[0] = 1;
  claim.amount_sats = 123456789;
  claim.program[0] = 3;
  if (version == 2) claim.script_kind = proofs::QuietProofScriptKind::kP2pkh;
  statement.claims.push_back(claim);
  return statement;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc != 2) return 1;
    const fs::path directory(argv[1]);
    fs::create_directories(directory);
    RequestState state;
    std::vector<uint8_t> original;
    for (int version : {1, 2}) {
      const auto statement = Statement(version);
      Check(proofs::EncodeQuietProofStatement(statement, &original), "encode supported request");
      auto path = directory / ("valid-v" + std::to_string(version) + ".qpr");
      Write(path, original);
      state.Open(path);
      Check(state.loaded && state.error == RequestError::None, "load supported request");
      Check(state.loaded->bytes == original && state.loaded->statement.statement_version == version &&
            state.loaded->statement.claims[0].script_kind == statement.claims[0].script_kind,
            "retain exact wire bytes and decoded version/kind");
    }
    static_assert(std::is_const_v<decltype(LoadedRequest::bytes)>);
    static_assert(std::is_const_v<decltype(LoadedRequest::statement)>);
    const auto retained = state.loaded;
    const auto revision = state.revision;
    state.Open(std::nullopt);
    Check(state.loaded == retained && state.revision == revision, "canceled chooser preserves selection");
    Write(directory / "valid-v2.qpr", {1});
    Check(retained->bytes == original, "loaded bytes independent of later file edits");
    auto reject = [&](const fs::path& path, RequestError error) {
      state.Open(directory / "valid-v1.qpr");
      const auto before = state.revision;
      state.Open(path);
      Check(!state.loaded && state.error == error && state.revision == before + 1,
            "failed replacement clears obsolete request and advances revision");
      Check(std::string(state.Message()).size() > 20, "actionable error text");
    };
    Write(directory / "malformed.qpr", {0, 1, 2, 3});
    reject(directory / "malformed.qpr", RequestError::Malformed);
    for (const auto size : {size_t{0}, size_t{5}, original.size() - 1}) {
      Write(directory / "truncated.qpr", {original.begin(), original.begin() + size});
      reject(directory / "truncated.qpr", RequestError::Malformed);
    }
    auto unsupported = original;
    unsupported[4] = 3;
    Write(directory / "unsupported.qpr", unsupported);
    reject(directory / "unsupported.qpr", RequestError::Unsupported);
    unsupported = original;
    unsupported[5] = 99;
    Write(directory / "network.qpr", unsupported);
    reject(directory / "network.qpr", RequestError::Unsupported);
    auto trailing = original;
    trailing.push_back(0);
    Write(directory / "trailing.qpr", trailing);
    reject(directory / "trailing.qpr", RequestError::Malformed);
    Write(directory / "oversized.qpr", std::vector<uint8_t>(4097));
    reject(directory / "oversized.qpr", RequestError::TooLarge);
    reject(directory / "missing.qpr", RequestError::Unreadable);
    reject(directory, RequestError::Unreadable);
    Write(directory / "unreadable.qpr", original);
    fs::permissions(directory / "unreadable.qpr", fs::perms::none);
    reject(directory / "unreadable.qpr", RequestError::Unreadable);
    fs::permissions(directory / "unreadable.qpr", fs::perms::owner_all);
    const auto unicode = directory / "Prüfung-東京.qpr";
    Write(unicode, original);
    state.Open(unicode);
    Check(state.loaded && state.loaded->path == unicode && state.loaded->bytes == original, "Unicode file path");
    for (int version : {1, 2}) {
      proofs::QuietProofEnvelopeV1 envelope;
      envelope.statement = Statement(version);
      envelope.envelope_version = version;
      envelope.proof_created_at = version == 2 ? 2 : 0;
      envelope.proof.bytes = {1};
      envelope.proof.circuit_digest[0] = 1;
      envelope.proof.circuit_version = proofs::PoKCParametersV1::kCircuitVersion;
      envelope.proof.rate = proofs::PoKCParametersV1::kRate;
      envelope.proof.queries = proofs::PoKCParametersV1::kQueries;
      std::vector<uint8_t> bytes;
      Check(proofs::EncodeQuietProofEnvelope(envelope, &bytes), "encode proof envelope fixture");
      const auto path = directory / ("proof-v" + std::to_string(version) + ".qpf");
      Write(path, bytes);
      reject(path, RequestError::ProofFile);
    }
    Write(directory / "large-proof.qpf", std::vector<uint8_t>(10000));
    { std::fstream proof(directory / "large-proof.qpf", std::ios::binary | std::ios::in | std::ios::out); proof.write("QPE1",4); }
    reject(directory / "large-proof.qpf", RequestError::ProofFile);
    RequestChooser chooser;
    chooser.Browse(unicode);
    Check(chooser.open && chooser.directory == directory && !chooser.entries.empty(), "chooser lists selected file folder");
    chooser.Cancel();
    Check(!chooser.open && state.error == RequestError::ProofFile, "chooser cancellation does not load a file");
    chooser.Browse(directory / "missing" / "file");
    Check(!chooser.error.empty(), "unreadable chooser folder error");
    Write(directory / "valid-v2.qpr", original);
    std::cout << "GUI request loader: " << checks << " checks passed; fixtures=" << directory << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
