#include "request_review.h"

#include <chrono>
#include <cstdio>

namespace quietproof::gui {
namespace {
template <size_t N>
std::string Hex(const std::array<uint8_t,N>& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string text;
  text.reserve(N*2);
  for (const auto byte : bytes) {
    text.push_back(digits[byte >> 4]);
    text.push_back(digits[byte & 15]);
  }
  return text;
}
}  // namespace

RequestWindow RequestWindowAt(const proofs::QuietProofStatementV1& statement, int64_t now) {
  if (!proofs::QuietProofStatementValid(statement)) return RequestWindow::Invalid;
  if (now < 0) return RequestWindow::ClockUnavailable;
  if (static_cast<uint64_t>(now) < statement.not_before) return RequestWindow::NotYetValid;
  if (static_cast<uint64_t>(now) >= statement.expires_at) return RequestWindow::Expired;
  return RequestWindow::Valid;
}
const char* RequestWindowName(RequestWindow window) {
  switch (window) {
    case RequestWindow::Valid: return "valid";
    case RequestWindow::NotYetValid: return "not-yet-valid";
    case RequestWindow::Expired: return "expired";
    case RequestWindow::ClockUnavailable: return "clock-unavailable";
    case RequestWindow::Invalid: return "invalid";
  }
  return "invalid";
}
const char* RequestWindowMessage(RequestWindow window) {
  switch (window) {
    case RequestWindow::Valid: return "Time window valid. Wallet readiness unchecked.";
    case RequestWindow::NotYetValid: return "Request not yet valid. Proving unavailable.";
    case RequestWindow::Expired: return "Request expired. Proving unavailable.";
    case RequestWindow::ClockUnavailable: return "Check your device clock. Proving unavailable.";
    case RequestWindow::Invalid: return "Invalid request. Proving unavailable.";
  }
  return "Invalid request. Proving unavailable.";
}

std::string RequestUtcTime(uint64_t seconds) {
  // Keep every uint64 wire value representable without narrowing or wrapping.
  if (seconds > 253402300799ULL)
    return "Unix " + std::to_string(seconds) + " seconds (UTC; outside calendar display range)";
  using namespace std::chrono;
  const sys_seconds point{std::chrono::seconds{static_cast<int64_t>(seconds)}};
  const auto day = floor<days>(point);
  const year_month_day date{day};
  const hh_mm_ss clock{point-day};
  char text[40];
  std::snprintf(text,sizeof(text),"%04d-%02u-%02u %02lld:%02lld:%02lld UTC",
      int(date.year()),unsigned(date.month()),unsigned(date.day()),
      static_cast<long long>(clock.hours().count()),static_cast<long long>(clock.minutes().count()),
      static_cast<long long>(clock.seconds().count()));
  return text;
}

std::string RequestAmount(uint64_t sats) {
  const auto fraction = std::to_string(sats % 100000000);
  return std::to_string(sats / 100000000) + "." + std::string(8-fraction.size(),'0') + fraction +
      " BTC (" + std::to_string(sats) + " sats)";
}

std::string RequestDisplayText(const std::string& text) {
  std::string display;
  for (size_t offset=0; offset<text.size();) {
    const auto lead = static_cast<uint8_t>(text[offset]);
    const size_t length = lead < 0x80 ? 1 : lead < 0xe0 ? 2 : lead < 0xf0 ? 3 : 4;
    if (offset+length > text.size()) { display += "[invalid UTF-8]"; break; }
    uint32_t codepoint = length == 1 ? lead : lead & ((1u << (7-length))-1);
    for (size_t i=1; i<length; ++i)
      codepoint = (codepoint << 6) | (static_cast<uint8_t>(text[offset+i]) & 0x3f);
    if (codepoint < 0x20 || codepoint == 0x7f ||
        (codepoint >= 0x200b && codepoint <= 0x200f) ||
        (codepoint >= 0x2028 && codepoint <= 0x202e) ||
        (codepoint >= 0x2060 && codepoint <= 0x206f) || codepoint == 0xfeff) {
      char escaped[20];
      std::snprintf(escaped,sizeof(escaped),"[U+%04X]",codepoint);
      display += escaped;
    } else display.append(text,offset,length);
    offset += length;
  }
  return display;
}

RequestReview InspectRequest(const proofs::QuietProofStatementV1& statement) {
  RequestReview review;
  review.statement_version = statement.statement_version;
  review.network = proofs::QuietProofNetworkName(statement.network);
  review.verifier = statement.verifier;
  review.purpose = statement.purpose;
  review.request_created_at = review.not_before = statement.not_before;
  review.expires_at = statement.expires_at;
  review.claim_count = statement.claims.size();
  review.has_snapshot = statement.has_snapshot;
  review.snapshot = Hex(statement.snapshot);
  review.snapshot_height = statement.snapshot_height;
  for (const auto& claim : statement.claims) {
    const std::string kind = proofs::QuietProofScriptKindName(claim.script_kind);
    const auto key_hash = Hex(claim.program);
    review.script_kinds.push_back(kind);
    review.claims.push_back({Hex(claim.txid),claim.vout,claim.amount_sats,kind,key_hash,
        claim.script_kind == proofs::QuietProofScriptKind::kP2wpkh ? "0014"+key_hash : "76a914"+key_hash+"88ac"});
    review.total_sats += claim.amount_sats;
  }
  return review;
}
}  // namespace quietproof::gui
