// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_DETAIL_BITCOIN_CORE_PARSE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_DETAIL_BITCOIN_CORE_PARSE_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cli/json.hpp"
#include "quietproof/statement.h"

namespace proofs {

constexpr size_t kQuietProofMaxRpcOutputBytes = size_t{1024} * 1024;

namespace quietproof_internal {

inline bool IsLowerHex(const std::string& value, size_t expected_size) {
  if (value.size() != expected_size) return false;
  for (char byte : value) {
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')))
      return false;
  }
  return true;
}

inline int HexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

inline bool DecodeHex(const std::string& value, std::vector<uint8_t>* output) {
  if (output == nullptr || value.size() % 2 != 0 ||
      !IsLowerHex(value, value.size())) return false;
  output->clear();
  output->reserve(value.size() / 2);
  for (size_t index = 0; index < value.size(); index += 2) {
    const int high = HexNibble(value[index]);
    const int low = HexNibble(value[index + 1]);
    output->push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return true;
}

inline bool JsonUnsigned(const nlohmann::json& value, uint64_t* output) {
  if (output == nullptr) return false;
  if (value.is_number_unsigned()) {
    *output = value.get<uint64_t>();
    return true;
  }
  if (value.is_number_integer()) {
    const int64_t signed_value = value.get<int64_t>();
    if (signed_value < 0) return false;
    *output = static_cast<uint64_t>(signed_value);
    return true;
  }
  return false;
}

inline bool BitcoinAmountToSats(const std::string& value, uint64_t* sats) {
  if (sats == nullptr || value.empty() || value[0] == '-') return false;
  const size_t decimal = value.find('.');
  if (value.find_first_of("eE") != std::string::npos ||
      (decimal != std::string::npos && value.find('.', decimal + 1) != std::string::npos))
    return false;
  const std::string whole_text = value.substr(0, decimal);
  std::string fractional = decimal == std::string::npos
                               ? std::string()
                               : value.substr(decimal + 1);
  if (whole_text.empty() || fractional.size() > 8) return false;
  uint64_t whole = 0;
  for (char digit : whole_text) {
    if (digit < '0' || digit > '9' ||
        whole > (kQuietProofMaxMoneySats / 100000000ULL -
                 static_cast<uint64_t>(digit - '0')) / 10) return false;
    whole = whole * 10 + static_cast<uint64_t>(digit - '0');
  }
  uint64_t fraction = 0;
  for (char digit : fractional) {
    if (digit < '0' || digit > '9') return false;
    fraction = fraction * 10 + static_cast<uint64_t>(digit - '0');
  }
  for (size_t index = fractional.size(); index < 8; ++index) fraction *= 10;
  if (whole > kQuietProofMaxMoneySats / 100000000ULL) return false;
  const uint64_t result = whole * 100000000ULL + fraction;
  if (result > kQuietProofMaxMoneySats) return false;
  *sats = result;
  return true;
}

struct Tip {
  std::string chain;
  std::string best_block_hash;
  uint64_t height = 0;
};

inline bool ParseTipFields(const nlohmann::json& json, Tip* tip) {
  if (tip == nullptr || !json.is_object() || !json.contains("chain") ||
      !json["chain"].is_string() || !json.contains("bestblockhash") ||
      !json["bestblockhash"].is_string() || !json.contains("blocks")) return false;
  Tip parsed;
  parsed.chain = json["chain"].get<std::string>();
  parsed.best_block_hash = json["bestblockhash"].get<std::string>();
  if (!IsLowerHex(parsed.best_block_hash, 64) ||
      !JsonUnsigned(json["blocks"], &parsed.height)) return false;
  *tip = std::move(parsed);
  return true;
}

inline bool ParseTip(const std::string& text, Tip* tip) {
  if (tip == nullptr || text.size() > kQuietProofMaxRpcOutputBytes) return false;
  const auto json = nlohmann::json::parse(text, nullptr, false);
  return ParseTipFields(json, tip);
}

inline bool TxOutShapeValid(const nlohmann::json& txout) {
  return txout.is_object() && txout.contains("bestblock") &&
         txout["bestblock"].is_string() && txout.contains("confirmations") &&
         txout.contains("value") && txout.contains("scriptPubKey") &&
         txout["scriptPubKey"].is_object() &&
         txout["scriptPubKey"].contains("hex") &&
         txout["scriptPubKey"]["hex"].is_string();
}

// amount_token must come from the original numeric value token, independently
// of the DOM's floating-point representation. The legacy raw-result tokenizer
// and the native envelope decoder supply it through their own decoding paths.
inline bool ParseTxOutFields(const nlohmann::json& txout,
                             const std::string& amount_token,
                             const std::string& expected_block,
                             uint64_t* amount_sats, uint64_t* confirmations,
                             std::vector<uint8_t>* script_pub_key) {
  if (amount_sats == nullptr || confirmations == nullptr ||
      script_pub_key == nullptr || !TxOutShapeValid(txout)) return false;
  const std::string best_block = txout["bestblock"].get<std::string>();
  const std::string script = txout["scriptPubKey"]["hex"].get<std::string>();
  return best_block == expected_block &&
         BitcoinAmountToSats(amount_token, amount_sats) &&
         JsonUnsigned(txout["confirmations"], confirmations) &&
         DecodeHex(script, script_pub_key);
}

}  // namespace quietproof_internal
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_DETAIL_BITCOIN_CORE_PARSE_H_
