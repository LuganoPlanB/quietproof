// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_AUTHORISATION_H_
#define QUIETPROOF_SIGNATURE_AUTHORISATION_H_

#include "quietproof/signature_digest.h"
#include "ec/p256k1.h"
#include "circuits/ripemd160/ripemd160.h"

namespace proofs {
constexpr size_t kQuietProofSignatureReceiptHeaderBytes = 45;
constexpr size_t kQuietProofSignatureMaxReceiptBytes = 4096;

// Private native witness material. Never log, publish, upload or treat this as
// a public proof. A future prover must still derive h/z from its own expected
// request and independently constrain the complete signature/HASH160 relation.
struct QuietProofSignatureAuthorisationV1 {
  std::array<uint8_t, 32> statement_digest{};
  std::array<uint8_t, 33> public_key{};
  std::array<uint8_t, 32> r{}, s{}; // Canonical big-endian scalar bytes.
};
enum class QuietProofSignatureAuthorisationError {
  kNone, kMalformedReceipt, kMalformedStatement, kUnsupported,
  kSignatureModeDisabled, kInvalidAuthorization
};
inline const char* QuietProofSignatureAuthorisationErrorName(QuietProofSignatureAuthorisationError error) {
  switch (error) {
    case QuietProofSignatureAuthorisationError::kNone: return "none";
    case QuietProofSignatureAuthorisationError::kMalformedReceipt: return "malformed_receipt";
    case QuietProofSignatureAuthorisationError::kMalformedStatement: return "malformed_statement";
    case QuietProofSignatureAuthorisationError::kUnsupported: return "unsupported";
    case QuietProofSignatureAuthorisationError::kSignatureModeDisabled: return "signature_mode_disabled";
    case QuietProofSignatureAuthorisationError::kInvalidAuthorization: return "invalid_authorization";
  }
  return "malformed_receipt";
}

namespace quietproof_detail {
// Borrowed bounded views only: no length-derived allocation while parsing a
// private transaction. Every CompactSize is checked before conversion/use.
class SignatureReceiptReader {
 public:
  SignatureReceiptReader(const uint8_t* data, size_t size) : data_(data), left_(size) {}
  bool take(size_t size, const uint8_t** data) {
    if (size > left_) return false;
    *data = data_; data_ += size; left_ -= size; return true;
  }
  bool copy(uint8_t* data, size_t size) {
    const uint8_t* view;
    if (!take(size, &view)) return false;
    if (size) std::memcpy(data, view, size);
    return true;
  }
  bool number(size_t width, uint64_t* value) {
    const uint8_t* bytes;
    if (width > 8 || !take(width, &bytes)) return false;
    *value = 0;
    for (size_t i = 0; i < width; ++i) *value |= uint64_t(bytes[i]) << (8 * i);
    return true;
  }
  bool compact(size_t maximum, size_t* value) {
    uint64_t first, decoded;
    if (!number(1, &first)) return false;
    decoded = first;
    if (first >= 253) {
      const size_t width = first == 253 ? 2 : first == 254 ? 4 : 8;
      if (!number(width, &decoded) || decoded < (width == 2 ? 253ULL :
          width == 4 ? 65536ULL : 4294967296ULL)) return false;
    }
    if (decoded > maximum) return false;
    *value = static_cast<size_t>(decoded); return true;
  }
  size_t left() const { return left_; }
 private:
  const uint8_t* data_;
  size_t left_;
};

struct ParsedSignatureReceipt {
  QuietProofScriptKind kind = QuietProofScriptKind::kP2wpkh;
  std::array<uint8_t, 36> outpoint{};
  std::array<uint8_t, 33> public_key{};
  std::array<uint8_t, 32> r{}, s{};
  uint8_t sighash = 0;
  bool fixed_fields = false;
  bool scalar_overflow = false;
};

inline bool SignatureReceiptDer(const uint8_t* signature, size_t size, ParsedSignatureReceipt* out) {
  // Maximum DER is 71 bytes for this low-S profile, plus its one-byte flag.
  if (size < 9 || size > 72 || signature[0] != 0x30 || signature[1] != size - 3) return false;
  SignatureReceiptReader reader(signature + 2, size - 3);
  for (auto* scalar : {&out->r, &out->s}) {
    scalar->fill(0);
    uint64_t tag, length;
    const uint8_t* bytes;
    if (!reader.number(1, &tag) || tag != 2 || !reader.number(1, &length) ||
        length == 0 || !reader.take(static_cast<size_t>(length), &bytes) ||
        (bytes[0] & 0x80) || (length > 1 && bytes[0] == 0 && !(bytes[1] & 0x80))) return false;
    if (length > 1 && bytes[0] == 0) { ++bytes; --length; }
    if (length > 32) { out->scalar_overflow = true; continue; }
    std::copy_n(bytes, static_cast<size_t>(length), scalar->end() - length);
  }
  if (reader.left()) return false;
  out->sighash = signature[size - 1];
  return true;
}

inline bool ParseSignatureReceiptTransaction(const uint8_t* bytes, size_t size, ParsedSignatureReceipt* out) {
  if (size < 105 || size > 171) return false;
  SignatureReceiptReader reader(bytes, size);
  uint64_t version, sequence, amount, locktime;
  size_t count, length;
  if (!reader.number(4, &version) || !reader.compact(1, &count)) return false;
  const bool witness = count == 0;
  if (witness) {
    uint64_t flag;
    if (!reader.number(1, &flag) || flag != 1 || !reader.compact(1, &count)) return false;
  }
  if (count != 1 || size < (witness ? 108u : 105u) || size > (witness ? 171u : 168u)) return false;
  out->kind = witness ? QuietProofScriptKind::kP2wpkh : QuietProofScriptKind::kP2pkh;
  if (!reader.copy(out->outpoint.data(), out->outpoint.size()) || !reader.compact(107, &length)) return false;
  const uint8_t* script;
  if (!reader.take(length, &script) || !reader.number(4, &sequence) ||
      !reader.compact(1, &count) || count != 1 || !reader.number(8, &amount)) return false;
  const size_t script_sig_size = length;
  const uint8_t* output_script;
  if (!reader.compact(kQuietProofSignatureMaxReceiptBytes, &length) || !reader.take(length, &output_script)) return false;
  const bool op_return = length == 1 && output_script[0] == 0x6a;
  const uint8_t* signature;
  size_t signature_size;
  if (witness) {
    if (script_sig_size != 0 || !reader.compact(2, &count) || count != 2 ||
        !reader.compact(72, &signature_size) || !reader.take(signature_size, &signature) ||
        !reader.compact(33, &length) || length != 33 || !reader.copy(out->public_key.data(), 33)) return false;
  } else {
    SignatureReceiptReader stack(script, script_sig_size);
    uint64_t push;
    if (!stack.number(1, &push) || push < 9 || push > 72) return false;
    signature_size = static_cast<size_t>(push);
    if (!stack.take(signature_size, &signature) || !stack.number(1, &push) || push != 33 ||
        !stack.copy(out->public_key.data(), 33) || stack.left()) return false;
  }
  if (!reader.number(4, &locktime) || reader.left() || !SignatureReceiptDer(signature, signature_size, out)) return false;
  out->fixed_fields = version == 0 && sequence == 0 && amount == 0 && locktime == 0 && op_return;
  return true;
}

inline Fp256k1Nat SignatureReceiptNat(const std::array<uint8_t, 32>& big_endian) {
  std::array<uint8_t, 32> little;
  std::reverse_copy(big_endian.begin(), big_endian.end(), little.begin());
  return Fp256k1Nat::of_bytes(little.data());
}

inline bool SignatureReceiptPublicKeyPoint(const std::array<uint8_t, 33>& key,
                                          P256k1::ECPoint* output) {
  const auto& f = p256k1_base;
  if (!output || (key[0] != 2 && key[0] != 3)) return false;
  std::array<uint8_t, 32> x_bytes;
  std::copy_n(key.begin() + 1, 32, x_bytes.begin());
  const auto x = SignatureReceiptNat(x_bytes);
  if (!(x < f.m_)) return false; // Reject raw coordinate aliases before Montgomery conversion.
  const auto xm = f.to_montgomery(x);
  const auto square = f.addf(f.mulf(f.mulf(xm, xm), xm), f.of_scalar(7));
  auto exponent = f.m_; exponent.add(Fp256k1Nat(1)); exponent.shiftr(2);
  auto y = f.one();
  for (size_t bit = 256; bit-- > 0;) {
    y = f.mulf(y, y);
    if (exponent.bit(bit)) y = f.mulf(y, square);
  }
  if (f.mulf(y, y) != square) return false;
  if (f.from_montgomery(y).bit(0) != (key[0] & 1)) y = f.negf(y);
  if (f.from_montgomery(y).bit(0) != (key[0] & 1)) return false;
  const P256k1::ECPoint q(xm, y, f.one());
  if (!p256k1.is_on_curve(q)) return false;
  *output = q;
  return true;
}

// Variable-time native verification, not a proof of circuit soundness.
inline bool SignatureReceiptEcdsaValid(const std::array<uint8_t, 32>& z,
    const std::array<uint8_t, 33>& key, const std::array<uint8_t, 32>& r_bytes,
    const std::array<uint8_t, 32>& s_bytes) {
  const auto& f = p256k1_base;
  const auto& sf = p256k1_scalar;
  const auto r = SignatureReceiptNat(r_bytes), s = SignatureReceiptNat(s_bytes);
  auto half = n256k1_order; half.shiftr(1);
  if (r == Fp256k1Nat(0) || !(r < n256k1_order) || s == Fp256k1Nat(0) || half < s) return false;
  P256k1::ECPoint q;
  if (!SignatureReceiptPublicKeyPoint(key, &q)) return false;
  auto e = SignatureReceiptNat(z);
  if (!(e < n256k1_order)) e.sub(n256k1_order); // e=0 and both digest reduction branches are valid.
  const auto inverse = sf.invertf(sf.to_montgomery(s));
  const auto u = sf.from_montgomery(sf.mulf(sf.to_montgomery(e), inverse));
  const auto v = sf.from_montgomery(sf.mulf(sf.to_montgomery(r), inverse));
  auto nonce = p256k1.addEf(p256k1.scalar_multf(p256k1.generator(), u), p256k1.scalar_multf(q, v));
  if (nonce.z == f.zero()) return false;
  p256k1.normalize(nonce);
  auto rx = f.from_montgomery(nonce.x);
  if (!(rx < n256k1_order)) rx.sub(n256k1_order); // Includes rare x(R)=r+n, since p<2n.
  return rx == r;
}
// Recover Q = r^-1(sR - eG) from the exact compact recovery header. Compressed
// P2PKH only. High-S is rejected, never normalized or paired with a new header.
// This variable-time host operation does not change the arithmetic circuit.
inline bool RecoverBitcoinMessageKey(const std::array<uint8_t, 32>& z,
    const uint8_t* compact, ParsedSignatureReceipt* output) {
  if (!compact || !output || compact[0] < 31 || compact[0] > 34) return false;
  ParsedSignatureReceipt parsed;
  parsed.kind = QuietProofScriptKind::kP2pkh;
  std::copy_n(compact + 1, 32, parsed.r.begin());
  std::copy_n(compact + 33, 32, parsed.s.begin());
  const auto r = SignatureReceiptNat(parsed.r), s = SignatureReceiptNat(parsed.s);
  auto half = n256k1_order; half.shiftr(1);
  if (r == Fp256k1Nat(0) || !(r < n256k1_order) ||
      s == Fp256k1Nat(0) || half < s) return false;
  const auto& f = p256k1_base;
  const auto& sf = p256k1_scalar;
  const unsigned recovery = compact[0] - 31;
  auto x = r;
  if (recovery & 2) {
    x.add(n256k1_order);
    if (x < r) return false;  // Fixed-width addition overflow.
  }
  if (!(x < f.m_)) return false;
  const auto xm = f.to_montgomery(x);
  const auto square = f.addf(f.mulf(f.mulf(xm, xm), xm), f.of_scalar(7));
  auto exponent = f.m_; exponent.add(Fp256k1Nat(1)); exponent.shiftr(2);
  auto y = f.one();
  for (size_t bit = 256; bit-- > 0;) {
    y = f.mulf(y, y);
    if (exponent.bit(bit)) y = f.mulf(y, square);
  }
  if (f.mulf(y, y) != square) return false;
  if (f.from_montgomery(y).bit(0) != (recovery & 1)) y = f.negf(y);
  const P256k1::ECPoint nonce(xm, y, f.one());
  if (!p256k1.is_on_curve(nonce) ||
      p256k1.scalar_multf(nonce, n256k1_order).z != f.zero()) return false;
  auto e = SignatureReceiptNat(z);
  if (!(e < n256k1_order)) e.sub(n256k1_order);
  const auto inverse = sf.invertf(sf.to_montgomery(r));
  const auto sr = sf.from_montgomery(sf.mulf(sf.to_montgomery(s), inverse));
  const auto er = sf.from_montgomery(sf.negf(sf.mulf(sf.to_montgomery(e), inverse)));
  auto key = p256k1.addEf(p256k1.scalar_multf(nonce, sr),
                        p256k1.scalar_multf(p256k1.generator(), er));
  if (key.z == f.zero()) return false;
  p256k1.normalize(key);
  if (!p256k1.is_on_curve(key)) return false;
  const auto qx = f.from_montgomery(key.x);
  parsed.public_key[0] = 2 + f.from_montgomery(key.y).bit(0);
  for (size_t i = 0; i < 32; ++i) {
    uint8_t byte = 0;
    for (size_t bit = 0; bit < 8; ++bit)
      if (qx.bit((31 - i) * 8 + bit)) byte |= uint8_t{1} << bit;
    parsed.public_key[1 + i] = byte;
  }
  if (!SignatureReceiptEcdsaValid(z, parsed.public_key, parsed.r, parsed.s)) return false;
  *output = parsed;
  return true;
}
}  // namespace quietproof_detail

// Explicit private/local import only. A parsed receipt does not select another
// mode or enable capability. No provider, upload, RPC or logging occurs here.
// Configuration-dependent entry has TU-local linkage. Failure changes no output.
static inline bool ImportQuietProofSignatureAuthorisation(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& receipt,
    QuietProofSignatureAuthorisationV1* output, QuietProofSignatureAuthorisationError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureAuthorisationError code) {
    if (error) *error = code;
    return false;
  };
  if (!output || receipt.size() < kQuietProofSignatureReceiptHeaderBytes ||
      receipt.size() > kQuietProofSignatureMaxReceiptBytes || std::memcmp(receipt.data(), "QPA1", 4))
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  if (receipt[4] != kQuietProofSignatureStatementVersion)
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  QuietProofReader header(receipt);
  uint8_t magic[4], version, mode, profile_version;
  uint16_t profile;
  uint32_t size;
  std::array<uint8_t, 32> digest;
  if (!header.bytes(magic,4) || !header.u8(&version) || !header.u8(&mode) || !header.u16(&profile) ||
      !header.u8(&profile_version) || !header.bytes(digest.data(),digest.size()) || !header.u32(&size) || size == 0 ||
      size > kQuietProofSignatureMaxReceiptBytes - kQuietProofSignatureReceiptHeaderBytes || size != header.left())
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  if (mode > 1 || !QuietProofSigningProfileDescriptorFor(
          static_cast<QuietProofSigningProfile>(profile), profile_version))
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  if (mode != kQuietProofSignatureMode) return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  QuietProofSignatureStatementV4 expected;
  QuietProofDecodeError decode_error;
  if (!DecodeQuietProofSignatureStatement(expected_request,&expected,&decode_error))
    return fail(decode_error == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureAuthorisationError::kUnsupported : QuietProofSignatureAuthorisationError::kMalformedStatement);
  if (profile != static_cast<uint16_t>(expected.signing_profile) ||
      profile_version != expected.profile_version)
    return fail(QuietProofSignatureAuthorisationError::kInvalidAuthorization);
  if (!QuietProofSigningProfileImplemented(expected.signing_profile))
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  quietproof_detail::ParsedSignatureReceipt parsed;
  const bool legacy = expected.signing_profile == QuietProofSigningProfile::kBitcoinMessageEcdsaV1;
  const auto* payload = receipt.data() + kQuietProofSignatureReceiptHeaderBytes;
  if (legacy) {
    if (size != 65) return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
    if (payload[0] < 31 || payload[0] > 34)
      return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  } else if (!quietproof_detail::ParseSignatureReceiptTransaction(payload,size,&parsed))
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
#if !defined(QUIETPROOF_HAS_SIGNATURE_MODE) || !QUIETPROOF_HAS_SIGNATURE_MODE
  return fail(QuietProofSignatureAuthorisationError::kSignatureModeDisabled);
#endif
  QuietProofSignatureInputsV1 inputs;
  if (!DeriveQuietProofSignatureInputs(expected_request,&inputs))
    return fail(QuietProofSignatureAuthorisationError::kMalformedStatement);
  if (legacy && !quietproof_detail::RecoverBitcoinMessageKey(inputs.z, payload, &parsed))
    return fail(QuietProofSignatureAuthorisationError::kInvalidAuthorization);
  if (digest != inputs.profile.statement_digest || parsed.kind != expected.signing_kind ||
      (!legacy && (!parsed.fixed_fields || parsed.outpoint != inputs.profile.synthetic_outpoint ||
                   parsed.sighash != 1 || parsed.scalar_overflow)))
    return fail(QuietProofSignatureAuthorisationError::kInvalidAuthorization);
  std::array<uint8_t, 32> hash;
  SHA256 sha; sha.Update(parsed.public_key.data(),parsed.public_key.size()); sha.DigestData(hash.data());
  if (Ripemd160::digest(hash) != inputs.profile.h ||
      !quietproof_detail::SignatureReceiptEcdsaValid(inputs.z,parsed.public_key,parsed.r,parsed.s))
    return fail(QuietProofSignatureAuthorisationError::kInvalidAuthorization);
  QuietProofSignatureAuthorisationV1 result;
  result.statement_digest = inputs.profile.statement_digest;
  result.public_key = parsed.public_key; result.r = parsed.r; result.s = parsed.s;
  *output = result;
  if (error) *error = QuietProofSignatureAuthorisationError::kNone;
  return true;
}
}  // namespace proofs
#endif
