// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_SCHEME_H_
#define QUIETPROOF_SIGNATURE_SCHEME_H_

#include <array>
#include <cstdint>
#include <string>

namespace proofs {
enum class QuietProofScriptKind : uint8_t { kP2wpkh = 0, kP2pkh = 1 };
enum class QuietProofSigningProfile : uint16_t {
  kBip322EcdsaV1 = 1,
  kBitcoinMessageEcdsaV1 = 2
};
constexpr uint8_t kQuietProofSigningProfileVersion = 1;

struct QuietProofSigningProfileDescriptor {
  QuietProofSigningProfile id;
  uint8_t version;
  const char* name;
  const char* label;
  bool p2wpkh;
  bool p2pkh;
};
inline constexpr std::array<QuietProofSigningProfileDescriptor, 2>
    kQuietProofSigningProfiles{{
      {QuietProofSigningProfile::kBip322EcdsaV1, 1, "bip322-ecdsa-v1", "BIP322 ECDSA", true, true},
      {QuietProofSigningProfile::kBitcoinMessageEcdsaV1, 1, "bitcoin-message-ecdsa-v1", "Bitcoin Signed Message (compressed P2PKH)", false, true}}};

inline const QuietProofSigningProfileDescriptor* QuietProofSigningProfileDescriptorFor(
    QuietProofSigningProfile id, uint8_t version = kQuietProofSigningProfileVersion) {
  for (const auto& descriptor : kQuietProofSigningProfiles)
    if (descriptor.id == id && descriptor.version == version) return &descriptor;
  return nullptr;
}
inline bool QuietProofSigningProfileCompatible(QuietProofSigningProfile id,
    uint8_t version, QuietProofScriptKind kind) {
  const auto* descriptor = QuietProofSigningProfileDescriptorFor(id, version);
  return descriptor && ((kind == QuietProofScriptKind::kP2wpkh && descriptor->p2wpkh) ||
                        (kind == QuietProofScriptKind::kP2pkh && descriptor->p2pkh));
}
inline const char* QuietProofSigningProfileName(QuietProofSigningProfile id) {
  const auto* descriptor = QuietProofSigningProfileDescriptorFor(id);
  return descriptor ? descriptor->name : "unsupported";
}
inline bool QuietProofParseSigningProfile(const std::string& name,
                                         QuietProofSigningProfile* output) {
  if (!output) return false;
  for (const auto& descriptor : kQuietProofSigningProfiles) {
    if (name == descriptor.name) { *output = descriptor.id; return true; }
  }
  return false;
}
inline bool QuietProofSigningProfileImplemented(QuietProofSigningProfile id) {
  return id == QuietProofSigningProfile::kBip322EcdsaV1 ||
         id == QuietProofSigningProfile::kBitcoinMessageEcdsaV1;
}
inline bool QuietProofDefaultSigningProfile(QuietProofScriptKind kind,
                                           QuietProofSigningProfile* output) {
  if (!output) return false;
  if (kind == QuietProofScriptKind::kP2pkh) *output = QuietProofSigningProfile::kBitcoinMessageEcdsaV1;
  else if (kind == QuietProofScriptKind::kP2wpkh) *output = QuietProofSigningProfile::kBip322EcdsaV1;
  else return false;
  return true;
}
inline const char* QuietProofSigningInstructions(QuietProofSigningProfile id, QuietProofScriptKind kind) {
  if (!QuietProofSigningProfileCompatible(id, 1, kind)) return "Unsupported signing profile and address kind";
  if (id == QuietProofSigningProfile::kBitcoinMessageEcdsaV1)
    return "Sign the exact message with Bitcoin Signed Message using compressed P2PKH; import bitcoin-message or Sparrow JSON.";
  return kind == QuietProofScriptKind::kP2pkh ?
      "Sign the exact message using BIP322 Full with compressed P2PKH; import bip322-full or Sparrow JSON." :
      "Sign the exact message using BIP322 Simple or Full with P2WPKH; import bip322-simple, bip322-full or Sparrow JSON.";
}
}  // namespace proofs
#endif
