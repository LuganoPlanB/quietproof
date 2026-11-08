// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only private fixture driver. Never echo witness-bearing JSON/errors.
#include <fstream>
#include <iostream>
#include "cli/json.hpp"
#include "quietproof/bitcoin_message_import.h"
#include "quietproof/bip322_import.h"
namespace {
using namespace proofs;
std::vector<uint8_t> Unhex(const std::string& s) {
  if (s.size() % 2 || s.size() > 32768) throw 1;
  std::vector<uint8_t> out;
  for (size_t i = 0; i < s.size(); i += 2) out.push_back(std::stoul(s.substr(i, 2), nullptr, 16));
  return out;
}
template<size_t N> std::array<uint8_t, N> Array(const nlohmann::json& value) {
  const auto bytes = Unhex(value.get<std::string>());
  if (bytes.size() != N) throw 1;
  std::array<uint8_t, N> out; std::copy(bytes.begin(), bytes.end(), out.begin()); return out;
}
void Check(bool value) { if (!value) throw 1; }
}
int main(int argc, char** argv) {
  try {
    Check(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(input)), {});
    Check(text.size() <= 8 * 1024 * 1024 && !input.bad());
    const auto fixture = nlohmann::json::parse(text);
    size_t count = 0, recovery_count = 0;
    for (const auto& t : fixture.at("cases")) {
      ++count;
      const auto request = Unhex(t.at("request"));
      std::vector<uint8_t> receipt{0xaa}; const auto before = receipt;
      QuietProofSignatureAuthorisationError error;
      bool accepted;
      if (t.value("transport", "bitcoin-message") == "receipt") {
        QuietProofSignatureAuthorisationV1 auth; auth.public_key.fill(0xaa);
        accepted = ImportQuietProofSignatureAuthorisation(request, Unhex(t.at("receipt")), &auth, &error);
        if (accepted) Check(auth.public_key == Array<33>(t.at("key")));
        else Check(std::all_of(auth.public_key.begin(), auth.public_key.end(), [](auto b) { return b == 0xaa; }));
      } else if (t.value("transport", "bitcoin-message") == "bip322-full") {
        accepted = ImportQuietProofBip322Signature(request, QuietProofBip322Format::kFull,
            t.at("signature"), &receipt, &error);
      } else {
        accepted = ImportQuietProofBitcoinMessageSignature(request, t.at("signature"), &receipt, &error);
      }
      if (std::string(QuietProofSignatureAuthorisationErrorName(error)) != t.at("expected").get<std::string>() ||
          accepted != (t.at("expected") == "none")) {
        std::cerr << "legacy case " << count << " classification=" << QuietProofSignatureAuthorisationErrorName(error) << '\n'; return 1;
      }
      if (t.value("transport", "bitcoin-message") != "receipt") {
        if (!accepted) Check(receipt == before);
        else {
          Check(receipt == Unhex(t.at("receipt")));
          QuietProofSignatureAuthorisationV1 auth;
          Check(ImportQuietProofSignatureAuthorisation(request, receipt, &auth));
          Check(auth.public_key == Array<33>(t.at("key")) && auth.r == Array<32>(t.at("r")) &&
                auth.s == Array<32>(t.at("s")) && auth.statement_digest == Array<32>(t.at("d")));
          QuietProofSignatureInputsV1 inputs;
          Check(DeriveQuietProofSignatureInputs(request, &inputs) && inputs.z == Array<32>(t.at("z")) &&
                inputs.sighash_preimage == Unhex(t.at("preimage")));
        }
      }
    }
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
    for (const auto& t : fixture.at("recovery")) {
      ++recovery_count;
      quietproof_detail::ParsedSignatureReceipt out;
      out.public_key.fill(0xaa); const auto before = out.public_key;
      const auto compact = Unhex(t.at("compact")); Check(compact.size() == 65);
      const bool ok = quietproof_detail::RecoverBitcoinMessageKey(Array<32>(t.at("z")), compact.data(), &out);
      Check(ok == t.at("valid").get<bool>());
      Check(ok ? out.public_key == Array<33>(t.at("key")) : out.public_key == before);
    }
#endif
    std::cout << "{\"cases\":" << count << ",\"recoveryCases\":" << recovery_count << ",\"failed\":0}" << '\n';
    return 0;
  } catch (...) { std::cerr << "private legacy fixture or execution failed\n"; return 1; }
}
