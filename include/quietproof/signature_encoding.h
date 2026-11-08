// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_ENCODING_H_
#define QUIETPROOF_SIGNATURE_ENCODING_H_
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
namespace proofs::quietproof_detail {
// Strict bounded RFC4648 transport only; it chooses no signing procedure.
inline bool DecodeQuietProofSignatureBase64(const std::string& text,
                                           std::vector<uint8_t>* output) {
  if (!output || text.empty() || text.size() > 228 || text.size() % 4) return false;
  const auto digit = [](char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
  };
  std::vector<uint8_t> decoded;
  for (size_t i = 0; i < text.size(); i += 4) {
    const int a = digit(text[i]), b = digit(text[i+1]);
    const bool pad_c = text[i+2] == '=', pad_d = text[i+3] == '=';
    const int c = pad_c ? 0 : digit(text[i+2]), d = pad_d ? 0 : digit(text[i+3]);
    if (a < 0 || b < 0 || c < 0 || d < 0 || (pad_c && !pad_d) ||
        ((pad_c || pad_d) && i + 4 != text.size()) ||
        (pad_c && (b & 15)) || (pad_d && !pad_c && (c & 3))) return false;
    decoded.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
    if (!pad_c) decoded.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
    if (!pad_d) decoded.push_back(static_cast<uint8_t>((c << 6) | d));
  }
  *output = std::move(decoded);
  return true;
}
}  // namespace proofs::quietproof_detail
#endif
