// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_TEST_SIGNATURE_CAPABILITY_PROBE_IMPL_H_
#define QUIETPROOF_TEST_SIGNATURE_CAPABILITY_PROBE_IMPL_H_
#include "probe.h"
#include "quietproof/signature_challenge.h"
#include "quietproof/signature_digest.h"
#include "quietproof/signature_authorisation.h"
#include "quietproof/signature_envelope.h"

// This test helper must also stay local; otherwise the test itself would
// introduce the same ODR defect it is meant to detect in the public header.
static SignatureCapabilityProbe RunSignatureProbe() {
  using namespace proofs;
  QuietProofClaimV1 claim;
  claim.txid.fill(1); claim.program.fill(1); claim.amount_sats = 1;
  QuietProofSignatureChallengeOptions options;
  options.request = {QuietProofNetwork::kRegtest, "capability-test", "proof-of-funds", "public fixture"};
  options.signing_kind = QuietProofScriptKind::kP2wpkh;
  QuietProofSignatureStatementV3 public_output, sourced_output;
  public_output.verifier = sourced_output.verifier = "unchanged";
  QuietProofSignatureChallengeError public_error{}, sourced_error{};
  SignatureCapabilityProbe result;
  result.capability = kQuietProofSignatureModeEnabled;
  result.public_result = CreateQuietProofSignatureChallenge({claim}, options, &public_output, &public_error);
  result.sourced_result = quietproof_detail::CreateQuietProofSignatureChallengeWithSources(
      {claim}, options, &sourced_output, &sourced_error, SignatureProbeClock, SignatureProbeRandom);
  const auto expected_error = result.capability ? QuietProofSignatureChallengeError::kNone :
      QuietProofSignatureChallengeError::kSignatureModeDisabled;
  result.expected_errors = public_error == expected_error && sourced_error == expected_error;
  QuietProofSignatureStatementV3 expected;
  expected.network = options.request.network; expected.verifier = options.request.verifier;
  expected.purpose = options.request.purpose; expected.nonce.fill(1); expected.bip322_message_hash.fill(1);
  expected.not_before = 100; expected.expires_at = 400; expected.claims = {claim};
  expected.signing_kind = options.signing_kind;
  std::vector<uint8_t> request;
  if (!EncodeQuietProofSignatureStatement(expected, &request)) return result;
  QuietProofSignatureInputsV1 inputs;
  QuietProofSignatureDigestError digest_error{};
  result.digest_result = DeriveQuietProofSignatureInputs(request, &inputs, &digest_error);
  result.expected_errors = result.expected_errors && digest_error == (result.capability ?
      QuietProofSignatureDigestError::kNone : QuietProofSignatureDigestError::kSignatureModeDisabled);
  // Well-framed private input with invalid authorization; OFF must stop at
  // capability, while ON reaches the later authorization rejection. No secrets.
  std::vector<uint8_t> body(4,0);
  body.push_back(1); body.insert(body.end(),36,0); body.push_back(44);
  body.insert(body.end(),{9,0x30,6,2,1,1,2,1,1,1,33});
  body.push_back(2); body.insert(body.end(),32,1); body.insert(body.end(),4,0);
  body.push_back(1); body.insert(body.end(),8,0); body.insert(body.end(),{1,0x6a}); body.insert(body.end(),4,0);
  std::vector<uint8_t> receipt{'Q','P','A','1',1,1,0,1};
  receipt.insert(receipt.end(),32,0); QuietProofAppendU32(&receipt,static_cast<uint32_t>(body.size()));
  receipt.insert(receipt.end(),body.begin(),body.end());
  QuietProofSignatureAuthorisationV1 authorization;
  QuietProofSignatureAuthorisationError receipt_error;
  const bool imported=ImportQuietProofSignatureAuthorisation(request,receipt,&authorization,&receipt_error);
  result.receipt_capability_checked=!imported && receipt_error==(result.capability ?
      QuietProofSignatureAuthorisationError::kInvalidAuthorization : QuietProofSignatureAuthorisationError::kSignatureModeDisabled);
  QuietProofSignatureEnvelopeMetadataV3 metadata;
  metadata.request=request; metadata.proof_created_at=100; metadata.circuit_digest.fill(1); // Test-only identity.
  std::vector<uint8_t> wire;
  QuietProofSignatureEnvelopeError envelope_error;
  std::array<uint8_t,32> seed; seed.fill(17);
  PoKSigPublicInputsV1 public_inputs;
  const bool public_encoded=PoKSigEncodePublicInputs(request,&public_inputs);
  result.envelope_capability_checked=EncodeQuietProofSignatureEnvelope(metadata,{1},&wire) &&
      !QuietProofSignatureEnvelopeSupported(wire,&envelope_error) && envelope_error==(result.capability ?
          QuietProofSignatureEnvelopeError::kUnapprovedCircuit : QuietProofSignatureEnvelopeError::kSignatureModeDisabled) &&
      !PoKSigTranscriptSeed(request,wire,100,&seed,&envelope_error) && seed[0]==17 &&
      envelope_error==(result.capability ? QuietProofSignatureEnvelopeError::kUnapprovedCircuit :
          QuietProofSignatureEnvelopeError::kSignatureModeDisabled) && public_encoded==result.capability;
  result.unchanged_or_valid_output = result.capability ?
      QuietProofSignatureStatementValid(public_output) && QuietProofSignatureStatementValid(sourced_output) &&
          sourced_output.not_before == 100 && sourced_output.expires_at == 400 &&
          inputs.profile.h == claim.program && !QuietProofAllZero(inputs.z) :
      public_output.verifier == "unchanged" && sourced_output.verifier == "unchanged" && QuietProofAllZero(inputs.z);
  return result;
}
#endif
