// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_ADDRESS_H_
#define QUIETPROOF_SIGNATURE_ADDRESS_H_
#include <string>
#include "quietproof/signature_profile.h"

namespace proofs {
// Fixed-profile address encoding for offline request inspection/import. Public
// network identity remains in the request: testnet3/4 and signet share addresses.
inline std::string QuietProofSignatureAddress(const QuietProofSignatureStatementV3& request) {
  if (!QuietProofSignatureStatementValid(request)) return {};
  const auto& program = request.claims.front().program;
  if (request.signing_kind == QuietProofScriptKind::kP2pkh) {
    std::array<uint8_t, 25> payload{};
    payload[0] = request.network == QuietProofNetwork::kMainnet ? 0 : 111;
    std::copy(program.begin(), program.end(), payload.begin() + 1);
    const auto hash = quietproof_detail::QuietProofSignatureHash256(payload.data(), 21);
    std::copy_n(hash.begin(), 4, payload.begin() + 21);
    constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string encoded;
    size_t zeros = 0;
    while (zeros < payload.size() && payload[zeros] == 0) ++zeros;
    for (size_t start = zeros; start < payload.size();) {
      unsigned remainder = 0;
      for (size_t i = start; i < payload.size(); ++i) {
        const unsigned value = remainder * 256 + payload[i];
        payload[i] = value / 58;
        remainder = value % 58;
      }
      encoded.push_back(alphabet[remainder]);
      while (start < payload.size() && payload[start] == 0) ++start;
    }
    encoded.append(zeros, '1');
    std::reverse(encoded.begin(), encoded.end());
    return encoded;
  }
  const std::string hrp = request.network == QuietProofNetwork::kMainnet ? "bc" :
      request.network == QuietProofNetwork::kRegtest ? "bcrt" : "tb";
  constexpr char alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  constexpr uint32_t generators[] = {0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
  uint32_t checksum = 1;
  const auto feed = [&](uint8_t value) {
    const uint32_t top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (int i = 0; i < 5; ++i) if ((top >> i) & 1) checksum ^= generators[i];
  };
  for (unsigned char c : hrp) feed(c >> 5);
  feed(0);
  for (unsigned char c : hrp) feed(c & 31);
  std::string address = hrp + "1q";
  feed(0);
  uint32_t accumulator = 0;
  int bits = 0;
  for (uint8_t byte : program) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const uint8_t digit = (accumulator >> bits) & 31;
      feed(digit);
      address += alphabet[digit];
    }
  }
  for (int i = 0; i < 6; ++i) feed(0);
  checksum ^= 1;
  for (int i = 5; i >= 0; --i) address += alphabet[(checksum >> (5*i)) & 31];
  return address;
}
}  // namespace proofs
#endif
