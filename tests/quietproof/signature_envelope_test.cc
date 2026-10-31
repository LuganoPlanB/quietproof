// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic circuit identities/proof bytes below are TEST ONLY, never approved.
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>
#include "cli/json.hpp"
#include "quietproof/envelope.h"
#include "quietproof/signature_challenge.h"
#include "quietproof/verifier.h"
#include "quietproof/browser.h"

namespace { bool track_allocations = false; size_t maximum_allocation = 0; }
void* operator new(std::size_t size) {
  if (track_allocations && size > maximum_allocation) maximum_allocation = size;
  if (void* result = std::malloc(size ? size : 1)) return result;
  throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
namespace {
using namespace proofs;
using Error = QuietProofSignatureEnvelopeError;
size_t checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
std::vector<uint8_t> Unhex(const std::string& text) {
  std::vector<uint8_t> output;
  for (size_t i=0; i<text.size(); i+=2) output.push_back(std::stoul(text.substr(i,2),nullptr,16));
  return output;
}
template<class T> std::string Hex(const T& bytes) {
  constexpr char digits[]="0123456789abcdef"; std::string result;
  for (uint8_t b:bytes) { result+=digits[b>>4]; result+=digits[b&15]; } return result;
}
void Put(std::vector<uint8_t>& bytes, size_t offset, uint64_t value, size_t size) {
  for(size_t i=0;i<size;++i) bytes[offset+size-1-i]=static_cast<uint8_t>(value>>(8*i));
}
QuietProofSignatureEnvelopeMetadataV3 Metadata(const std::vector<uint8_t>& request) {
  QuietProofSignatureEnvelopeMetadataV3 m; m.request=request; m.proof_created_at=1800000100;
  for (size_t i=0;i<32;++i) m.circuit_digest[i]=i+1;
  return m;
}
void Reject(const std::vector<uint8_t>& wire, Error expected) {
  QuietProofSignatureEnvelopeMetadataV3 output; output.request={0xaa}; output.proof_created_at=17;
  Error error=Error::kNone;
  maximum_allocation=0; track_allocations=true;
  const bool result=InspectQuietProofSignatureEnvelope(wire,&output,&error);
  track_allocations=false;
  Check(!result && error==expected,"inspection rejection or attribution mismatch");
  Check(output.request==std::vector<uint8_t>{0xaa} && output.proof_created_at==17,"inspection changed failure output");
  Check(maximum_allocation<=kQuietProofMaxStatementBytes,"inspection allocated proof/unsafe length");
  error=Error::kNone;
  Check(!QuietProofSignatureEnvelopeSupported(wire,&error) && error==expected,"support bypassed framing/dispatch");
}
void Unapproved(const std::vector<uint8_t>& wire, const std::vector<uint8_t>& request) {
  Error error=Error::kNone;
  const auto expected=kQuietProofSignatureModeEnabled ? Error::kUnapprovedCircuit : Error::kSignatureModeDisabled;
  maximum_allocation=0; track_allocations=true;
  const bool supported=QuietProofSignatureEnvelopeSupported(wire,&error);
  track_allocations=false;
  Check(!supported && error==expected,"synthetic circuit became production support");
  Check(maximum_allocation<=kQuietProofMaxStatementBytes,"unsupported proof allocated");
  std::array<uint8_t,32> seed; seed.fill(0xaa); const auto before=seed;
  Check(!PoKSigTranscriptSeed(request,wire,UINT64_MAX,&seed,&error) && seed==before && error==expected,
      "production transcript accepted unapproved identity or changed output");
  Check(!PoKSigCircuitIdentityApproved(Metadata(request).circuit_digest),"test identity approved");
  QuietProofEnvelopeV1 scalar; scalar.proof_created_at=17;
  QuietProofDecodeError legacy; const char* reason=nullptr;
  Check(!DecodeQuietProofEnvelopeWithReason(wire,&scalar,&legacy,&reason) && legacy==QuietProofDecodeError::kUnsupported &&
      scalar.proof_created_at==17,"v3 reached scalar parser");
  unsigned callbacks=0;
  QuietProofVerifierConfig config; config.supports=[&](const auto&){++callbacks;return true;};
  config.verify_proof=[&](const auto&){++callbacks;return true;};
  config.policy.consume_nonce=[&](const auto&){++callbacks;return true;};
  Check(VerifyQuietProof(wire,config).result==QuietProofVerifyResult::kUnsupported && callbacks==0,
      "v3 reached scalar proof/provider/nonce callbacks");
}
void TupleMatrix(const std::vector<uint8_t>& wire, const std::vector<uint8_t>& request) {
  QuietProofSignatureStatementV3 signature;
  Check(DecodeQuietProofSignatureStatement(request,&signature),"matrix request decode");
  for(uint8_t statement_version:{uint8_t{1},uint8_t{2},uint8_t{3},uint8_t{4}}) {
    auto nested=request;
    if(statement_version<=2) {
      auto old=static_cast<QuietProofStatementV1>(signature);old.statement_version=statement_version;
      if(statement_version==1)for(auto& c:old.claims)c.script_kind=QuietProofScriptKind::kP2wpkh;
      Check(EncodeQuietProofStatement(old,&nested),"matrix old encoding");
      for(uint8_t version:{uint8_t{1},uint8_t{2}}) {
        QuietProofEnvelopeV1 legacy;legacy.statement=old;legacy.envelope_version=version;
        legacy.proof_created_at=version==1?0:1800000100;
        legacy.proof.circuit_digest.fill(1);legacy.proof.bytes={1};
        std::vector<uint8_t> oldwire;const bool allowed=version==2 || statement_version==1;
        Check(EncodeQuietProofEnvelope(legacy,&oldwire)==allowed,"old tuple encode changed");
        if(allowed){QuietProofEnvelopeV1 decoded;Check(DecodeQuietProofEnvelope(oldwire,&decoded),"old allowed tuple rejected");}
      }
    } else nested[4]=statement_version;
    auto base=wire;
    base.erase(base.begin()+9,base.begin()+9+request.size());base.insert(base.begin()+9,nested.begin(),nested.end());
    Put(base,5,nested.size(),4);const size_t tail=9+nested.size();
    for(uint8_t version:{uint8_t{1},uint8_t{2},uint8_t{3},uint8_t{4}})
    for(uint8_t mode:{uint8_t{0},uint8_t{1},uint8_t{2}})
    for(uint16_t profile:{uint16_t{1},uint16_t{2}})
    for(uint16_t family:{uint16_t{1},uint16_t{2}})
    for(uint32_t circuit:{1u,2u})for(uint32_t rate:{4u,8u})for(uint32_t queries:{128u,64u}) {
      auto candidate=base;candidate[4]=version;candidate[tail+8]=mode;
      Put(candidate,tail+9,profile,2);Put(candidate,tail+11,family,2);
      Put(candidate,tail+45,circuit,4);Put(candidate,tail+49,rate,4);Put(candidate,tail+53,queries,4);
      const bool unknown=version==4 || statement_version==4 || mode==2 || profile!=1 || family!=1 || circuit!=1 || rate!=4 || queries!=128;
      const bool allowed=!unknown && version==3 && statement_version==3 && mode==1;
      if(allowed) {
        QuietProofSignatureEnvelopeMetadataV3 m;Check(InspectQuietProofSignatureEnvelope(candidate,&m),"allowed v3 tuple rejected");
        Unapproved(candidate,request);
      } else Reject(candidate,unknown?Error::kUnsupported:Error::kMalformedStatement);
    }
  }
}
void Test(const nlohmann::json& vector) {
  auto request=Unhex(vector.at("request_hex")); auto metadata=Metadata(request);
  std::vector<uint8_t> wire;
  Check(EncodeQuietProofSignatureEnvelope(metadata,{1,2,3},&wire),"transport codec failed");
  Check(wire.size()==70+request.size()+3,"wrong overhead");
  const size_t tail=9+request.size();
  Check(Hex(std::vector<uint8_t>(wire.begin()+tail+8,wire.begin()+tail+13))=="0100010001","wrong mode/profile/family bytes");
  QuietProofSignatureEnvelopeMetadataV3 parsed;
  Check(InspectQuietProofSignatureEnvelope(wire,&parsed) && parsed.request==request && parsed.proof_size==3 &&
      parsed.proof_offset==70+request.size(),"inspection roundtrip failed");
  std::vector<uint8_t> again; Check(EncodeQuietProofSignatureEnvelope(parsed,{1,2,3},&again) && wire==again,"noncanonical roundtrip");
  Unapproved(wire,request);
  TupleMatrix(wire,request);
  for (size_t i=0;i<wire.size();++i) Reject({wire.begin(),wire.begin()+i},Error::kMalformedStatement);
  auto changed=wire; changed.push_back(0); Reject(changed,Error::kMalformedStatement);
  for (uint64_t value:{0ULL,4097ULL,0xffffffffULL}) {changed=wire;Put(changed,5,value,4);Reject(changed,Error::kMalformedStatement);}
  for (uint64_t value:{0ULL,2ULL,4ULL,134217729ULL,0xffffffffULL}) {changed=wire;Put(changed,tail+57,value,4);Reject(changed,Error::kMalformedStatement);}
  for (size_t offset:{size_t{0},size_t{1},size_t{2},size_t{3}}) {changed=wire;changed[offset]^=1;Reject(changed,Error::kMalformedStatement);}
  for (const auto [offset,size]:std::vector<std::pair<size_t,size_t>>{{4,1},{tail+8,1},{tail+9,2},{tail+11,2},
      {tail+45,4},{tail+49,4},{tail+53,4},{9+4,1},{9+5,1},{9+6,1},{9+7,2},{9+9,1}}) {
    for(uint64_t value:{2ULL,255ULL,0xffffffffULL}) {
      if ((offset==4 || offset==13 || offset==14) && value==2) continue; // Known versions/network.
      changed=wire;Put(changed,offset,value,size);Reject(changed,Error::kUnsupported);
      auto framed=changed;Put(framed,tail+57,0xffffffff,4);Reject(framed,Error::kMalformedStatement);
      changed[tail+8]=0; // Unknown ID still wins over known outer mode0.
      if(offset!=tail+8) Reject(changed,Error::kUnsupported);
    }
  }
  for(size_t offset:{tail+45,tail+49,tail+53}) {changed=wire;Put(changed,offset,0,4);Reject(changed,Error::kUnsupported);}
  for(uint8_t version:{uint8_t{1},uint8_t{2}}) {changed=wire;changed[4]=version;Reject(changed,Error::kMalformedStatement);}
  for(size_t offset:{tail+8,size_t{9+6}}) {changed=wire;changed[offset]=0;Reject(changed,Error::kMalformedStatement);}
  changed=wire; std::fill_n(changed.begin()+tail+13,32,0);Reject(changed,Error::kMalformedStatement);
  // Use genuinely encoded old statements, preserving nested ID attribution.
  QuietProofSignatureStatementV3 s;Check(DecodeQuietProofSignatureStatement(request,&s),"fixture decode");
  for(uint8_t sv:{uint8_t{1},uint8_t{2}}) {
    auto old=static_cast<QuietProofStatementV1>(s);old.statement_version=sv;
    if(sv==1) for(auto& c:old.claims)c.script_kind=QuietProofScriptKind::kP2wpkh;
    std::vector<uint8_t> oldwire;Check(EncodeQuietProofStatement(old,&oldwire),"old statement fixture");
    changed=wire;changed.erase(changed.begin()+9,changed.begin()+tail);changed.insert(changed.begin()+9,oldwire.begin(),oldwire.end());Put(changed,5,oldwire.size(),4);
    Reject(changed,Error::kMalformedStatement);
    changed[9+5]=255;Reject(changed,Error::kUnsupported);
  }
  for(uint64_t t:{0ULL,1799999999ULL,1800000600ULL,0xffffffffffffffffULL}) {
    changed=wire;Put(changed,tail,t,8);Reject(changed,Error::kMalformedStatement);
  }
  for(uint64_t t:{1800000000ULL,1800000599ULL}) {
    changed=wire;Put(changed,tail,t,8);Check(InspectQuietProofSignatureEnvelope(changed,&parsed),"timestamp boundary rejected");
    Unapproved(changed,request);
  }
  // Exact 53 SDK plucker elements, independently sourced h,z fixture bytes.
  PoKSigPublicInputsV1 public_inputs; for(auto& e:public_inputs)e=p256k1_base.of_scalar(17);
  auto before=public_inputs; QuietProofSignatureDigestError input_error;
  const bool encoded=PoKSigEncodePublicInputs(request,&public_inputs,&input_error);
  if(kQuietProofSignatureModeEnabled) {
    Check(encoded && input_error==QuietProofSignatureDigestError::kNone,"public input encoding failed");
    Check(public_inputs[0]==p256k1_base.one(),"public constant missing");
    auto bytes=Unhex(vector.at("request").at("claims")[0].at("program").get<std::string>()+vector.at("z").get<std::string>());
    BitPluckerEncoder<Fp256k1Base,8> encoder(p256k1_base);
    for(size_t i=0;i<52;++i)Check(public_inputs[i+1]==encoder.encode(bytes[i]),"public input offset/order/encoding differs");
    Check(public_inputs[1]!=p256k1_base.of_scalar(bytes[0]),"plucker confused with raw byte scalar");
    std::array<uint8_t,146> binding;
    Error error;
    Check(quietproof_detail::SignatureTranscriptBinding(request,metadata,1800000100,&binding,&error),"layout codec failed");
    const std::string expected=vector.at("name")=="p2pkh" ?
        "1d32c7cab58523e77acafbd8e452dd0bdff19dbd5102ac9d4fd73ab0281021e4" :
        "e671dae52a4fe5c6d155cc3c0dba92c0ae5d120f1fb3340ae351abcafb88a74d";
    auto seed=QuietProofTaggedHash(kPoKSigTranscriptDomain,binding.data(),binding.size());
    Check(Hex(seed)==expected,"transcript differs from independent frozen Python/hashlib vector");
    Check(Hex(std::vector<uint8_t>(binding.begin(),binding.begin()+10))=="51504531030100010001","binding leading bytes");
    Check(Hex(std::vector<uint8_t>(binding.begin()+10,binding.begin()+42))==vector.at("d").get<std::string>(),"binding d");
    Check(Hex(std::vector<uint8_t>(binding.begin()+42,binding.begin()+62))==vector.at("request").at("claims")[0].at("program").get<std::string>(),"binding h");
    Check(Hex(std::vector<uint8_t>(binding.begin()+62,binding.begin()+94))==vector.at("z").get<std::string>(),"binding z");
    for(size_t i=0;i<146;++i){auto b=binding;b[i]^=1;Check(QuietProofTaggedHash(kPoKSigTranscriptDomain,b.data(),b.size())!=seed,"binding byte not committed");}
    for(const char* tag:{"PoKC/transcript/v1","PoKC/transcript/v2","QuietProof/P2SH-2of3/proof/v1"})
      Check(QuietProofTaggedHash(tag,binding.data(),binding.size())!=seed,"old transcript domain reused");
    auto sentinel=binding;
    Check(!quietproof_detail::SignatureTranscriptBinding(request,metadata,1800000099,&binding,&error) && error==Error::kInvalidProof && binding==sentinel,"future proof time accepted/changed output");
    auto switched=request;switched[10+2]^=1; // A different retained request must never reuse embedded authorization.
    Check(!quietproof_detail::SignatureTranscriptBinding(switched,metadata,UINT64_MAX,&binding,&error) && binding==sentinel,"switched expected request accepted");
    auto modified=s;modified.nonce[0]^=1;Check(EncodeQuietProofSignatureStatement(modified,&switched),"mutated expected encode");
    Check(!quietproof_detail::SignatureTranscriptBinding(switched,metadata,UINT64_MAX,&binding,&error) && error==Error::kInvalidProof && binding==sentinel,"mutated expected request accepted");
    auto newmetadata=metadata;newmetadata.request=switched;
    Check(quietproof_detail::SignatureTranscriptBinding(switched,newmetadata,UINT64_MAX,&binding) && binding!=sentinel,"changed request reused public values");
    Check(!PoKSigTranscriptSeed(switched,wire,UINT64_MAX,&seed,&error) && error==Error::kUnapprovedCircuit,"request mutation bypassed approval");
    for(const auto& mutation:vector.at("field_mutations")) {
      auto changed_request=request;changed_request[mutation.at("offset").get<size_t>()]^=1;
      QuietProofSignatureStatementV3 changed_statement;
      if(!DecodeQuietProofSignatureStatement(changed_request,&changed_statement))continue;
      Check(!quietproof_detail::SignatureTranscriptBinding(changed_request,metadata,UINT64_MAX,&binding,&error) &&
          error==Error::kInvalidProof,"committed expected field mismatch accepted");
      auto changed_metadata=metadata;changed_metadata.request=changed_request;
      Check(quietproof_detail::SignatureTranscriptBinding(changed_request,changed_metadata,UINT64_MAX,&binding),"changed canonical layout failed");
      const auto& expected_mutation=mutation.at("field")=="signing_kind" ? vector.at("valid_selected_kind_change") : mutation;
      Check(Hex(std::vector<uint8_t>(binding.begin()+10,binding.begin()+42))==expected_mutation.at("d").get<std::string>() &&
          Hex(std::vector<uint8_t>(binding.begin()+62,binding.begin()+94))==expected_mutation.at("z").get<std::string>(),
          "expected request mutation differs from independent frozen public binding");
    }
    for(size_t i=0;i<32;++i) {
      auto changed_identity=metadata;changed_identity.circuit_digest[i]^=1;
      Check(quietproof_detail::SignatureTranscriptBinding(request,changed_identity,UINT64_MAX,&binding) && binding!=sentinel,"circuit identity omitted from binding");
      std::vector<uint8_t> unapproved;Check(EncodeQuietProofSignatureEnvelope(changed_identity,{1},&unapproved),"mutated identity codec");
      Unapproved(unapproved,request);
    }
  } else {
    Check(!encoded && input_error==QuietProofSignatureDigestError::kSignatureModeDisabled,"disabled public encoder ran");
    for(size_t i=0;i<53;++i)Check(public_inputs[i]==before[i],"disabled public encoder changed output");
  }
  {
    std::array<uint8_t,32> seed;seed.fill(17);const auto before_seed=seed;Error error;
    auto unknown_expected=request;unknown_expected[7]=0xff;
    Check(!PoKSigTranscriptSeed(unknown_expected,wire,UINT64_MAX,&seed,&error) && error==Error::kUnsupported && seed==before_seed,"unknown expected ID attribution");
    Check(!PoKSigTranscriptSeed({},wire,UINT64_MAX,&seed,&error) && error==Error::kMalformedStatement && seed==before_seed,"missing expected request attribution");
  }
  // True input buffer at the maximum proof bound: parser never copies proof.
  std::vector<uint8_t> huge(wire.begin(),wire.begin()+tail+61);
  huge.resize(tail+61+kQuietProofSignatureMaxProofBytes,1);Put(huge,tail+57,kQuietProofSignatureMaxProofBytes,4);
  maximum_allocation=0;track_allocations=true;
  const bool maximum=InspectQuietProofSignatureEnvelope(huge,&parsed);
  track_allocations=false;
  Check(maximum && maximum_allocation<=4096,"maximum proof framing allocated/copied proof");
  Unapproved(huge,request);
  auto invalid_metadata=metadata;invalid_metadata.profile=2;std::vector<uint8_t> transport{17};
  // Input proof already exists; rejecting an unsupported encode must not copy it.
  std::vector<uint8_t> proof(huge.begin()+tail+61,huge.end());
  maximum_allocation=0;track_allocations=true;
  const bool invalid_encoded=EncodeQuietProofSignatureEnvelope(invalid_metadata,proof,&transport);
  track_allocations=false;
  Check(!invalid_encoded && transport==std::vector<uint8_t>{17} && maximum_allocation<=4096,"unsupported encoder allocated proof/changed output");
  huge.push_back(0);Put(huge,tail+57,kQuietProofSignatureMaxProofBytes+1,4);Reject(huge,Error::kMalformedStatement);
  huge.resize(kQuietProofSignatureMaxEnvelopeBytes+1);Reject(huge,Error::kMalformedStatement);
  // Truncated/renamed private input stays local and never reaches callbacks.
  for(size_t size:{size_t{4},size_t{44},size_t{4096}}) {
    std::vector<uint8_t> receipt(size,0);std::copy_n("QPA1",4,receipt.begin());
    Reject(receipt,Error::kPrivateReceiptInput);
    QuietProofVerifierConfig config;unsigned callbacks=0;
    config.verify_proof=[&](const auto&){++callbacks;return true;};
    const char* reason=nullptr;
    const auto result=VerifyQuietProofWithReason(receipt,config,&reason);
    Check(result.result==QuietProofVerifyResult::kMalformedStatement && reason &&
        std::string(reason)=="private_receipt_input" && callbacks==0,"public receipt rejection reason/callbacks");
    std::vector<uint8_t> browser{17};Check(!QuietProofBrowserInspect(receipt,true,&browser) && browser==std::vector<uint8_t>{17},"browser receipt inspection disclosed bytes");
  }
}
void CircuitIdentityAlgorithm() {
  // Tiny synthetic serializable circuit, explicitly not the signature relation.
  Circuit<Fp256k1Base> circuit{};circuit.nv=1;circuit.nc=1;circuit.npub_in=53;circuit.ninputs=53;
  auto identity=PoKSigCircuitDigest(circuit);
  std::vector<uint8_t> bytes;CircuitWriter<Fp256k1Base>(p256k1_base,SECP_ID).to_bytes(circuit,bytes);
  // Frozen independently encoded prefix: family/u32 parameters/u64 circuit size.
  std::vector<uint8_t> binding=Unhex("0001000000010000000400000080");
  QuietProofAppendU64(&binding,bytes.size());binding.insert(binding.end(),bytes.begin(),bytes.end());
  Check(identity==QuietProofTaggedHash("QuietProof/signature/circuit/v1",binding.data(),binding.size()),"circuit identity serialization/domain");
  Check(!PoKSigCircuitIdentityApproved(identity),"synthetic serialized circuit approved");
  circuit.id[0]=1;Check(PoKSigCircuitDigest(circuit)!=identity,"actual serialized circuit omitted from digest");
}
} // namespace
int main(int argc,char** argv) {
  try {
    Check(argc==2,"fixture path required");std::ifstream file(argv[1]);nlohmann::json fixture;file>>fixture;
    for(const auto& vector:fixture.at("vectors"))Test(vector);
    CircuitIdentityAlgorithm();
    std::cout<<checks<<" envelope checks; synthetic identities TEST ONLY; production signature support unavailable\n";
    return 0;
  } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
