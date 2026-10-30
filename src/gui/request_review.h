#pragma once

#include "quietproof/statement.h"

#include <optional>
#include <string>
#include <vector>

namespace quietproof::gui {
enum class RequestWindow { Valid, NotYetValid, Expired, ClockUnavailable, Invalid };
RequestWindow RequestWindowAt(const proofs::QuietProofStatementV1& statement, int64_t now);
const char* RequestWindowName(RequestWindow window);
const char* RequestWindowMessage(RequestWindow window);
std::string RequestUtcTime(uint64_t seconds);
std::string RequestAmount(uint64_t sats);
// Escape invisible directional/layout controls for display. Wire values stay exact.
std::string RequestDisplayText(const std::string& text);

struct ClaimReview {
  std::string txid;
  uint32_t vout;
  uint64_t amount_sats;
  std::string script_kind;
  std::string key_hash;
  std::string script_hex;
};
struct RequestReview {
  std::string format = "quietproof-request-v1";
  uint8_t statement_version;
  std::string network;
  std::string verifier;
  std::string purpose;
  uint64_t request_created_at;
  uint64_t not_before;
  uint64_t expires_at;
  std::optional<uint64_t> proof_created_at;
  size_t claim_count;
  std::vector<std::string> script_kinds;
  bool has_snapshot;
  std::string snapshot;
  uint32_t snapshot_height;
  std::vector<ClaimReview> claims;
  uint64_t total_sats = 0;
};
// Presentation only: no I/O, wallet APIs, replay authorization or chain checks.
RequestReview InspectRequest(const proofs::QuietProofStatementV1& statement);
}  // namespace quietproof::gui
