// SPDX-License-Identifier: GPL-3.0-or-later
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "context.h"
using namespace proofs;
#define CHECK(x) do { if (!(x)) { std::cerr << "Failed line " << __LINE__ << ": " #x "\n"; return 1; } } while (0)
std::vector<uint8_t> Read(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
QuietProofBrowserPolicy Policy(const QuietProofStatementV1& s, const std::vector<uint8_t>& request) {
  // Original aggregate initialization remains source compatible and selects
  // key knowledge by default, including in a signature-enabled executable.
  return {s.network,s.verifier,s.purpose,"",s.bip322_message_hash,request,86400,0,0,60};
}
int main(int argc, char** argv) {
  static_assert(!kQuietProofSignatureModeEnabled); // Context starts in a base-only TU.
  QuietProofClaimV1 claim; claim.txid.fill(1); claim.program.fill(1); claim.amount_sats=1;
  QuietProofStatementV1 s; s.network=QuietProofNetwork::kMainnet; s.verifier="cross-tu.example";
  s.purpose="proof-of-funds"; s.nonce.fill(1); s.not_before=100; s.expires_at=400; s.claims={claim};
  s.bip322_message_hash.fill(1);
  std::vector<uint8_t> request; CHECK(EncodeQuietProofStatement(s,&request));
  auto p=Policy(s,request);
  CHECK(!p.allow_signature_possession);
  QuietProofEnvelopeV1 envelope; envelope.statement=s; envelope.envelope_version=2;
  envelope.proof_created_at=101; envelope.proof.circuit_digest.fill(1); envelope.proof.bytes={1};
  QuietProofBrowserVerification context;
  CHECK(context.Prepare(envelope,p,102));
  CHECK(ConsumeLegacyBrowserContext(context)); // Definition lives in another TU.
#ifdef QUIETPROOF_TEST_BROWSER_MIXED
  QuietProofSignatureStatementV4 signature;
  static_cast<QuietProofStatementV1&>(signature)=s; signature.statement_version=4;
  signature.signing_kind=QuietProofScriptKind::kP2wpkh;
  CHECK(EncodeQuietProofSignatureStatement(signature,&request));
  p=Policy(signature,request); p.allow_signature_possession=true;
  QuietProofSignatureEnvelopeMetadataV4 m; m.request=request; m.proof_created_at=101;
  m.circuit_digest=PoKSigExpectedCircuitDigest();
  std::vector<uint8_t> proof; CHECK(EncodeQuietProofSignatureEnvelope(m,{1},&proof));
  CHECK(PrepareEnabledBrowserSignature(&context,proof,p,102));
  CHECK(CheckPreparedBrowserContext(context,102));
  CHECK(!PrepareDisabledBrowserSignature(&context,proof,p,102));
  CHECK(context.phase()==QuietProofBrowserVerification::Phase::kEmpty && context.unsupported());
  CHECK(std::string(context.error())=="signature_mode_disabled");
  CHECK(PrepareEnabledBrowserSignature(&context,proof,p,102));
  CHECK(context.Prepare(envelope,Policy(s,{}),102)); // Old operation replaces signature binding.
  CHECK(ConsumeLegacyBrowserContext(context));
  size_t verified=0;
  if (argc==2) {
    for (const std::string name : {"signature-p2pkh","signature-p2wpkh","signature-mixed"}) {
      const std::filesystem::path root(argv[1]);
      request=Read(root/(name+".qpr")); proof=Read(root/(name+".qpf"));
      CHECK(DecodeQuietProofSignatureStatement(request,&signature));
      p=Policy(signature,request); p.allow_signature_possession=true;
      const auto now=[] { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); };
      CHECK(PrepareEnabledBrowserSignature(&context,proof,p,now()));
      CHECK(CheckPreparedBrowserContext(context,now()));
      CHECK(VerifyBrowserContextInDisabledTu(context,now()));
      CHECK(context.outcome().crypto==QuietProofBrowserCrypto::kValid);
      CHECK(context.outcome().explorer==QuietProofExplorerResult::kUnavailable);
      CHECK(!PrepareDisabledBrowserSignature(&context,proof,p,now()));
      CHECK(std::string(context.error())=="signature_mode_disabled");
      ++verified; std::cout << name << ": enabled preparation, base-only verification valid\n";
    }
    CHECK(verified==3);
  }
  std::cout << "cross-TU legacy context, mixed capability, real proofs=" << verified << " passed\n";
#else
  CHECK(argc==1);
  std::cout << "cross-TU legacy context passed\n";
#endif
}
