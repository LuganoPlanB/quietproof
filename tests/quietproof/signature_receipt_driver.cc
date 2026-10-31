// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Private test-file input only; diagnostics never serialize witness material.
#include <fstream>
#include <iostream>
#include <string>
#include "cli/json.hpp"
#include "quietproof/signature_authorisation.h"

namespace {
using namespace proofs;
std::vector<uint8_t> Unhex(const std::string& text) {
  if (text.size() % 2 || text.size() > 8194) throw 1;
  const auto nibble = [](char c) { return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1; };
  std::vector<uint8_t> bytes;
  for (size_t i=0; i<text.size(); i+=2) {
    if (nibble(text[i]) < 0 || nibble(text[i+1]) < 0) throw 1;
    bytes.push_back(static_cast<uint8_t>(16*nibble(text[i])+nibble(text[i+1])));
  }
  return bytes;
}
template <size_t N>
bool Matches(const std::array<uint8_t,N>& actual, const nlohmann::json& expected) {
  const auto bytes = Unhex(expected.get<std::string>());
  return bytes.size() == N && std::equal(bytes.begin(),bytes.end(),actual.begin());
}
template <size_t N>
std::array<uint8_t,N> Array(const nlohmann::json& value) {
  const auto bytes=Unhex(value.get<std::string>());
  if(bytes.size()!=N) throw 1;
  std::array<uint8_t,N> out; std::copy(bytes.begin(),bytes.end(),out.begin()); return out;
}
}
int main(int argc, char** argv) {
  try {
    if(argc!=2) throw 1;
    std::ifstream stream(argv[1],std::ios::binary);
    std::string text;
    std::array<char,4096> buffer;
    while(stream) {
      stream.read(buffer.data(),buffer.size()); text.append(buffer.data(),static_cast<size_t>(stream.gcount()));
      if(text.size()>8*1024*1024) throw 1;
    }
    if(stream.bad()) throw 1;
    const auto fixture=nlohmann::json::parse(text);
    if(ImportQuietProofSignatureAuthorisation({}, {}, nullptr)) throw 1;
    size_t count=0;
    for(const auto& test:fixture.at("cases")) {
      ++count;
      const auto request=Unhex(test.at("request").get<std::string>());
      const auto receipt=Unhex(test.at("receipt").get<std::string>());
      QuietProofSignatureAuthorisationV1 output;
      output.statement_digest.fill(0xaa); output.public_key.fill(0xbb); output.r.fill(0xcc); output.s.fill(0xdd);
      const auto before=output;
      QuietProofSignatureAuthorisationError error=QuietProofSignatureAuthorisationError::kNone;
      const bool accepted=ImportQuietProofSignatureAuthorisation(request,receipt,&output,&error);
      const auto expected=test.at("expected").get<std::string>();
      if(std::string(QuietProofSignatureAuthorisationErrorName(error))!=expected || accepted!=(expected=="none")) {
        std::cerr<<"receipt case "<<count<<" classification mismatch: "
                 <<QuietProofSignatureAuthorisationErrorName(error)<<'\n'; return 1;
      }
      const bool correct=accepted ? Matches(output.public_key,test.at("key")) && Matches(output.r,test.at("r")) &&
          Matches(output.s,test.at("s")) && Matches(output.statement_digest,test.at("d")) :
          output.statement_digest==before.statement_digest && output.public_key==before.public_key &&
          output.r==before.r && output.s==before.s;
      if(!correct) { std::cerr<<"receipt case "<<count<<" output mismatch\n"; return 1; }
    }
    size_t math=0;
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
    for(const auto& test:fixture.at("math")) {
      ++math;
      if(quietproof_detail::SignatureReceiptEcdsaValid(Array<32>(test.at("z")),Array<33>(test.at("key")),
          Array<32>(test.at("r")),Array<32>(test.at("s")))!=test.at("valid").get<bool>()) {
        std::cerr<<"native verification reference case "<<math<<" mismatch\n"; return 1;
      }
    }
#endif
    std::cout<<count<<" private receipt cases and "<<math<<" native verification cases passed\n";
    return 0;
  } catch(...) { std::cerr<<"private receipt test input or execution failed\n"; return 1; }
}
