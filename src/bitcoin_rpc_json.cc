// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include "bitcoin_rpc_json.h"

#include <limits>
#include <set>
#include <utility>
#include <vector>

#include "quietproof/detail/bitcoin_core_parse.h"

namespace proofs::bitcoin_rpc_internal {
namespace {
using Json = nlohmann::json;
bool Failure(BitcoinRpcError* error, BitcoinRpcErrorCode code, const char* message,
             int status, std::optional<int64_t> rpc_code = std::nullopt) {
  if (error) *error = {code, status, rpc_code, message};
  return false;
}
struct PathPart {
  std::string key;
  bool array_index = false;
};
using Path = std::vector<PathPart>;
bool IsMoneyPath(const Path& path) {
  if (path.empty() || path[0].array_index || path[0].key != "result") return false;
  if (path.size() == 2)
    return !path[1].array_index && path[1].key == "value";
  if (path.size() == 3)
    return path[1].array_index && !path[2].array_index && path[2].key == "amount";
  return path.size() == 4 && !path[1].array_index && path[1].key == "unspents" &&
         path[2].array_index && !path[3].array_index && path[3].key == "amount";
}
std::string MoneyPointer(const Path& path) {
  std::string pointer;
  for (const auto& part : path) { pointer += '/'; pointer += part.key; }
  return pointer;
}
class ResponseSax final : public nlohmann::json_sax<Json> {
 public:
  Json root;
  std::map<std::string, ExactMoney> money;
  bool null() override { return Scalar(nullptr); }
  bool boolean(bool value) override { return Scalar(value); }
  bool number_integer(number_integer_t value) override {
    return Number(value, std::to_string(value));
  }
  bool number_unsigned(number_unsigned_t value) override {
    return Number(value, std::to_string(value));
  }
  bool number_float(number_float_t value, const string_t& token) override {
    return Number(value, token);
  }
  bool string(string_t& value) override { return Scalar(std::move(value)); }
  bool binary(binary_t&) override { return false; }
  bool start_object(std::size_t) override { return Start(true); }
  bool start_array(std::size_t) override { return Start(false); }
  bool key(string_t& key) override {
    if (frames_.empty() || !frames_.back().object) return false;
    auto& frame = frames_.back();
    if (!frame.keys.insert(key).second) return false;
    frame.key = key;
    return true;
  }
  bool end_object() override { return End(true); }
  bool end_array() override { return End(false); }
  // Use the public json::exception alias; no nlohmann parser internals.
  bool parse_error(std::size_t, const std::string&, const Json::exception&) override {
    return false;
  }
 private:
  struct Frame {
    Json* value;
    Path path;
    bool object;
    std::string key;
    std::set<std::string> keys;
  };
  std::vector<Frame> frames_;
  bool has_root_ = false;
  Path NextPath() const {
    if (frames_.empty()) return {};
    const auto& parent = frames_.back();
    auto path = parent.path;
    path.push_back({parent.object ? parent.key : std::to_string(parent.value->size()), !parent.object});
    return path;
  }
  Json* Append(Json value) {
    if (frames_.empty()) {
      if (has_root_) return nullptr;
      has_root_ = true;
      root = std::move(value);
      return &root;
    }
    auto& frame = frames_.back();
    if (frame.object) {
      auto& target = (*frame.value)[frame.key];
      target = std::move(value);
      return &target;
    }
    frame.value->push_back(std::move(value));
    return &frame.value->back();
  }
  bool Scalar(Json value) {
    if (IsMoneyPath(NextPath())) return false;  // Numeric strings/null/booleans fail.
    return Append(std::move(value)) != nullptr;
  }
  template <typename Numeric>
  bool Number(Numeric value, const std::string& token) {
    const auto path = NextPath();
    if (IsMoneyPath(path)) {
      uint64_t sats = 0;
      if (!quietproof_internal::BitcoinAmountToSats(token, &sats) || sats == 0) return false;
      money.emplace(MoneyPointer(path), ExactMoney{token, sats});
      return Append(nullptr) != nullptr;
    }
    return Append(value) != nullptr;
  }
  bool Start(bool object) {
    if (frames_.size() >= kMaxJsonDepth) return false;
    auto path = NextPath();
    if (IsMoneyPath(path)) return false;
    auto* value = Append(object ? Json::object() : Json::array());
    if (!value) return false;
    frames_.push_back({value, std::move(path), object, {}, {}});
    return true;
  }
  bool End(bool object) {
    if (frames_.empty() || frames_.back().object != object) return false;
    frames_.pop_back();
    return true;
  }
};
bool SignedRpcCode(const Json& value, int64_t* output) {
  if (value.is_number_unsigned()) {
    const auto code = value.get<uint64_t>();
    if (code > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
    *output = static_cast<int64_t>(code);
    return true;
  }
  if (!value.is_number_integer()) return false;
  *output = value.get<int64_t>();
  return true;
}
}  // namespace

void EraseRpcJson(nlohmann::json& value) noexcept {
  if (value.is_string()) {
    auto& text = value.get_ref<std::string&>();
    volatile char* p = text.data();
    for (size_t i = 0; i < text.size(); ++i) p[i] = 0;
  } else if (value.is_array() || value.is_object()) {
    for (auto& child : value) EraseRpcJson(child);
  }
}

bool DecodeRpcResponse(const HttpResponse& response, const std::string& expected_id,
                       RpcDecodedResponse* output, BitcoinRpcError* error) {
  if (!output || expected_id.empty())
    return Failure(error, BitcoinRpcErrorCode::kConfiguration, "Invalid RPC decoder arguments", response.status);
  if (response.body.size() > kMaxBodyBytes)
    return Failure(error, BitcoinRpcErrorCode::kResponseTooLarge, "RPC response exceeds its byte limit", response.status);
  if (response.status == 401)
    return Failure(error, BitcoinRpcErrorCode::kAuthentication, "RPC cookie authentication failed", response.status);
  const bool http_ok = response.status >= 200 && response.status < 300;
  auto malformed = [&] {
    return Failure(error, http_ok ? BitcoinRpcErrorCode::kMalformed : BitcoinRpcErrorCode::kHttp,
                   http_ok ? "Malformed JSON-RPC response" : "RPC HTTP status indicates failure", response.status);
  };
  try {
    if (response.body.find('\0') != std::string::npos) return malformed();
    ResponseSax sax;
    struct EraseParsedValues {
      Json& value;
      ~EraseParsedValues() { EraseRpcJson(value); }
    } erase{sax.root};
    if (!Json::sax_parse(response.body, &sax, Json::input_format_t::json, true)) return malformed();
    const auto& envelope = sax.root;
    if (!envelope.is_object() || !envelope.contains("jsonrpc") ||
        !envelope["jsonrpc"].is_string() || envelope["jsonrpc"] != "2.0" ||
        !envelope.contains("id") || !envelope["id"].is_string() || envelope["id"] != expected_id ||
        envelope.contains("result") == envelope.contains("error")) return malformed();
    if (envelope.contains("error")) {
      const auto& rpc_error = envelope["error"];
      int64_t code = 0;
      if (!rpc_error.is_object() || !rpc_error.contains("code") ||
          !SignedRpcCode(rpc_error["code"], &code) || !rpc_error.contains("message") ||
          !rpc_error["message"].is_string() ||
          rpc_error["message"].get_ref<const std::string&>().size() > kMaxRpcErrorMessageBytes)
        return malformed();
      return Failure(error, BitcoinRpcErrorCode::kRpc, "Bitcoin Core RPC request failed", response.status, code);
    }
    if (!http_ok)
      return Failure(error, BitcoinRpcErrorCode::kHttp, "RPC HTTP status indicates failure", response.status);
    RpcDecodedResponse decoded;
    decoded.result = std::move(sax.root["result"]);
    decoded.money = std::move(sax.money);
    *output = std::move(decoded);
    if (error) *error = {};
    return true;
  } catch (...) {
    return malformed();  // No JSON exception or server text crosses the boundary.
  }
}

RpcClient::RpcClient(BitcoinCoreRpcConfig config, HttpTransport transport)
    : config_(std::move(config)), transport_(transport) {}
bool RpcClient::Call(const std::string& method, const Json& params, bool scan,
                     RpcDecodedResponse* output, BitcoinRpcError* error,
                     const std::optional<std::string>& wallet) {
  if (!output || !transport_ || exhausted_ || method.empty() || method.size() > 64 || !params.is_array())
    return Failure(error, BitcoinRpcErrorCode::kConfiguration, "Invalid RPC request arguments", 0);
  const std::string id = std::to_string(next_id_);
  if (next_id_ == std::numeric_limits<uint64_t>::max()) exhausted_ = true;
  else ++next_id_;
  try {
    Json request = {{"jsonrpc", "2.0"}, {"id", id}, {"method", method}};
    std::string body;
    struct EraseUnlockRequest {
      Json& request;
      std::string& body;
      bool sensitive;
      ~EraseUnlockRequest() {
        if (!sensitive) return;
        const auto parameters = request.find("params");
        if (parameters != request.end() && parameters->is_array() &&
            !parameters->empty() && (*parameters)[0].is_string()) {
          auto& text = (*parameters)[0].get_ref<std::string&>();
          volatile char* p = text.data();
          for (size_t i = 0; i < text.size(); ++i) p[i] = 0;
        }
        volatile char* p = body.data();
        for (size_t i = 0; i < body.size(); ++i) p[i] = 0;
      }
    } erase_request{request, body, method == "walletpassphrase" && !params.empty() && params[0].is_string()};
    request["params"] = params;
    body = request.dump();  // Only REQUESTS are serialized.
    HttpResponse response;
    struct EraseExportBody {
      HttpResponse& response;
      bool sensitive;
      ~EraseExportBody() {
        if (!sensitive) return;
        volatile char* bytes = response.body.data();
        for (size_t i = 0; i < response.body.size(); ++i) bytes[i] = 0;
      }
    } erase{response, method == "exportaddresskey" || method == "walletpassphrase"};
    BitcoinRpcError transport_error;
    const bool received = transport_(config_, body, scan, &response, &transport_error, wallet);
    if (!received && (transport_error.code != BitcoinRpcErrorCode::kHttp || response.status == 0)) {
      if (error) *error = std::move(transport_error);
      return false;
    }
    return DecodeRpcResponse(response, id, output, error);
  } catch (...) {
    return Failure(error, BitcoinRpcErrorCode::kConfiguration, "RPC request could not be serialized", 0);
  }
}
}  // namespace proofs::bitcoin_rpc_internal
