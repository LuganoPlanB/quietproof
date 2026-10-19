// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#include "quietproof/bitcoin_rpc.h"

#include <utility>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <set>
#include <string_view>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>

#include "bitcoin_rpc_internal.h"
#include "bitcoin_rpc_json.h"
#include "quietproof/detail/bitcoin_core_parse.h"

namespace proofs::bitcoin_rpc_internal {
namespace {
bool Fail(BitcoinRpcError* error, BitcoinRpcErrorCode code,
          const char* message, int status = 0) {
  if (error) *error = {code, status, std::nullopt, message};
  return false;
}
void ClearError(BitcoinRpcError* error) {
  if (error) *error = {};
}
bool CurlReady() {
  // Deliberately no global cleanup: other application threads may still use curl.
  static const CURLcode initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  return initialized == CURLE_OK;
}
struct CurlUrlDelete { void operator()(CURLU* p) const { curl_url_cleanup(p); } };
struct CurlStringDelete { void operator()(char* p) const { curl_free(p); } };
struct CurlEasyDelete { void operator()(CURL* p) const { curl_easy_cleanup(p); } };
struct CurlHeadersDelete {
  void operator()(curl_slist* p) const { curl_slist_free_all(p); }
};
using Url = std::unique_ptr<CURLU, CurlUrlDelete>;
using CurlString = std::unique_ptr<char, CurlStringDelete>;
using Easy = std::unique_ptr<CURL, CurlEasyDelete>;
using Headers = std::unique_ptr<curl_slist, CurlHeadersDelete>;
class File {
 public:
  explicit File(int fd) : fd_(fd) {}
  ~File() { if (fd_ >= 0) close(fd_); }
  int get() const { return fd_; }
  File(const File&) = delete;
  File& operator=(const File&) = delete;
 private:
  int fd_;
};
struct Cookie {
  std::array<char, kMaxCookieBytes + 1> bytes{};
  const char* username = nullptr;
  const char* password = nullptr;
  ~Cookie() {
    volatile char* p = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) p[i] = 0;
  }
};
bool IsLoopback(std::string_view host) {
  if (host.empty() || host.size() >= INET6_ADDRSTRLEN) return false;
  const std::string text(host);
  in_addr ipv4{};
  if (inet_pton(AF_INET, text.c_str(), &ipv4) == 1)
    return (ntohl(ipv4.s_addr) >> 24) == 127;
  in6_addr ipv6{};
  return inet_pton(AF_INET6, text.c_str(), &ipv6) == 1 &&
         IN6_IS_ADDR_LOOPBACK(&ipv6);
}
bool ValidRawEndpoint(const std::string& url) {
  // Validate the literal host BEFORE curl normalizes alternate IPv4 forms.
  constexpr std::string_view prefix = "http://";
  for (unsigned char c : url) if (c < 33 || c > 126) return false;
  if (!url.starts_with(prefix) || url.size() > 256 ||
      url.find_first_of("?#@\\") != std::string::npos) return false;
  const auto start = prefix.size();
  const auto slash = url.find('/', start);
  if (slash != std::string::npos && url.substr(slash) != "/") return false;
  const std::string_view authority(url.data() + start,
      (slash == std::string::npos ? url.size() : slash) - start);
  std::string_view host;
  std::string_view port;
  bool has_port = false;
  if (authority.starts_with('[')) {
    const auto end = authority.find(']');
    if (end == std::string_view::npos) return false;
    host = authority.substr(1, end - 1);
    const auto suffix = authority.substr(end + 1);
    if (!suffix.empty()) {
      if (!suffix.starts_with(':')) return false;
      has_port = true;
      port = suffix.substr(1);
    }
  } else {
    const auto colon = authority.find(':');
    host = authority.substr(0, colon);
    if (colon != std::string_view::npos) {
      has_port = true;
      port = authority.substr(colon + 1);
    }
  }
  if (!IsLoopback(host)) return false;
  if (has_port) {
    if (port.empty() || port.size() > 5) return false;
    unsigned value = 0;
    for (char c : port) {
      if (c < '0' || c > '9') return false;
      value = value * 10 + static_cast<unsigned>(c - '0');
    }
    if (value == 0 || value > 65535) return false;
  }
  return true;
}
bool ValidDuration(std::chrono::milliseconds duration) {
  constexpr auto maximum = std::chrono::hours(24);
  return duration.count() > 0 && duration <= maximum &&
         static_cast<uint64_t>(duration.count()) <=
             static_cast<uint64_t>(std::numeric_limits<long>::max());
}
bool ReadCookie(const std::string& path, Cookie* cookie, BitcoinRpcError* error) {
  File file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat metadata{};
  if (file.get() < 0 || fstat(file.get(), &metadata) != 0 ||
      !SecureCookieMetadata(metadata.st_mode, metadata.st_uid, geteuid()))
    return Fail(error, BitcoinRpcErrorCode::kCookie,
                "RPC cookie must be a readable regular owner-only file owned by this user");
  std::size_t size = 0;
  while (size < cookie->bytes.size()) {
    const auto count = read(file.get(), cookie->bytes.data() + size,
                            cookie->bytes.size() - size);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return Fail(error, BitcoinRpcErrorCode::kCookie,
                             "RPC cookie could not be read");
    if (count == 0) break;
    size += static_cast<std::size_t>(count);
  }
  if (size == 0 || size > kMaxCookieBytes)
    return Fail(error, BitcoinRpcErrorCode::kCookie, "RPC cookie size is invalid");
  if (cookie->bytes[size - 1] == '\n') --size;
  for (std::size_t i = 0; i < size; ++i) {
    const auto c = static_cast<unsigned char>(cookie->bytes[i]);
    if (c < 32 || c >= 127)
      return Fail(error, BitcoinRpcErrorCode::kCookie, "RPC cookie contains invalid bytes");
  }
  const auto begin = cookie->bytes.data();
  const auto colon = static_cast<char*>(std::memchr(begin, ':', size));
  if (!colon || colon == begin || colon == begin + size - 1)
    return Fail(error, BitcoinRpcErrorCode::kCookie, "RPC cookie credentials are malformed");
  *colon = 0;
  cookie->bytes[size] = 0;
  cookie->username = begin;
  cookie->password = colon + 1;
  return true;
}
bool EqualsAsciiCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; };
    if (lower(a[i]) != lower(b[i])) return false;
  }
  return true;
}
}  // namespace

bool SecureCookieMetadata(mode_t mode, uid_t owner, uid_t effective_user) {
  return S_ISREG(mode) && owner == effective_user && (mode & 077) == 0;
}

bool ResolveRpcConfig(const BitcoinCoreRpcConfig& config,
                      ResolvedRpcConfig* output, BitcoinRpcError* error) {
  if (!output || !ValidDuration(config.connect_timeout) ||
      !ValidDuration(config.rpc_timeout) || !ValidDuration(config.scan_timeout))
    return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                "RPC timeouts must be positive and at most 24 hours");
  const char* port = nullptr;
  const char* subdir = nullptr;
  switch (config.network) {
    case QuietProofNetwork::kMainnet: port = "8332"; subdir = ""; break;
    case QuietProofNetwork::kTestnet3: port = "18332"; subdir = "testnet3/"; break;
    case QuietProofNetwork::kSignet: port = "38332"; subdir = "signet/"; break;
    case QuietProofNetwork::kRegtest: port = "18443"; subdir = "regtest/"; break;
    case QuietProofNetwork::kTestnet4: port = "48332"; subdir = "testnet4/"; break;
    default: return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                         "An explicit supported RPC network is required");
  }
  ResolvedRpcConfig resolved;
  resolved.url = config.rpc_url.empty() ?
      std::string("http://127.0.0.1:") + port + "/" : config.rpc_url;
  if (!ValidRawEndpoint(resolved.url))
    return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                "RPC URL must be numeric loopback HTTP with a root path and valid port");
  if (!CurlReady())
    return Fail(error, BitcoinRpcErrorCode::kConnection, "HTTP initialization failed");
  Url parsed(curl_url());
  char* normalized = nullptr;
  if (!parsed || curl_url_set(parsed.get(), CURLUPART_URL, resolved.url.c_str(), 0) != CURLUE_OK ||
      curl_url_get(parsed.get(), CURLUPART_URL, &normalized, 0) != CURLUE_OK)
    return Fail(error, BitcoinRpcErrorCode::kConfiguration, "RPC URL is invalid");
  CurlString owned_url(normalized);
  resolved.url = owned_url.get();
  if (!config.rpc_cookie.empty()) {
    resolved.cookie_path = config.rpc_cookie;
  } else {
    std::string datadir = config.rpc_datadir;
    if (datadir.empty()) {
      const char* home = std::getenv("HOME");
      if (!home || home[0] != '/')
        return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                    "Specify an explicit RPC cookie or datadir when HOME is unavailable");
#if defined(__APPLE__)
      datadir = std::string(home) + "/Library/Application Support/Bitcoin";
#elif defined(__linux__)
      datadir = std::string(home) + "/.bitcoin";
#else
      return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                  "Specify an explicit RPC cookie or datadir on this platform");
#endif
    }
    if (datadir.back() != '/') datadir += '/';
    resolved.cookie_path = datadir + subdir + ".cookie";
  }
  if (resolved.cookie_path.find('\0') != std::string::npos)
    return Fail(error, BitcoinRpcErrorCode::kConfiguration, "RPC cookie path is invalid");
  *output = std::move(resolved);
  ClearError(error);
  return true;
}

std::size_t HttpBodyCallback(char* data, std::size_t size, std::size_t count,
                             void* context) noexcept {
  auto& buffers = *static_cast<HttpBuffers*>(context);
  if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) {
    buffers.too_large = true;
    return 0;
  }
  const auto bytes = size * count;
  if (buffers.body.size() > kMaxBodyBytes || bytes > kMaxBodyBytes - buffers.body.size()) {
    buffers.too_large = true;
    return 0;
  }
  try {
    buffers.body.append(data, bytes);
    return bytes;
  } catch (...) {
    buffers.buffer_failure = true;
    return 0;
  }
}
std::size_t HttpHeaderCallback(char* data, std::size_t size, std::size_t count,
                               void* context) noexcept {
  auto& buffers = *static_cast<HttpBuffers*>(context);
  if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) {
    buffers.too_large = true;
    return 0;
  }
  const auto bytes = size * count;
  if (buffers.header_bytes > kMaxHeaderBytes || bytes > kMaxHeaderBytes - buffers.header_bytes) {
    buffers.too_large = true;
    return 0;
  }
  buffers.header_bytes += bytes;
  const std::string_view header(data, bytes);
  // libcurl delivers obsolete folded headers one line at a time. Reject a
  // continuation rather than letting it alter a previously checked encoding.
  if (!header.empty() && (header.front() == ' ' || header.front() == '\t')) {
    buffers.unsupported_encoding = true;
    return 0;
  }
  const auto colon = header.find(':');
  if (colon != std::string_view::npos &&
      EqualsAsciiCase(header.substr(0, colon), "Content-Encoding")) {
    auto value = header.substr(colon + 1);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' ||
                              value.back() == '\r' || value.back() == '\n')) value.remove_suffix(1);
    if (!EqualsAsciiCase(value, "identity")) {
      buffers.unsupported_encoding = true;
      return 0;
    }
  }
  return bytes;
}

bool PostRpcHttp(const BitcoinCoreRpcConfig& config, const std::string& request,
                 bool scan, HttpResponse* output, BitcoinRpcError* error,
                 const std::optional<std::string>& wallet) {
  if (!output || request.size() > kMaxBodyBytes)
    return Fail(error, BitcoinRpcErrorCode::kConfiguration, "Invalid HTTP request buffer");
  ResolvedRpcConfig resolved;
  if (!ResolveRpcConfig(config, &resolved, error)) return false;
  if (wallet) {
    if (wallet->empty() || wallet->size() > 1024 || !QuietProofUtf8(*wallet))
      return Fail(error, BitcoinRpcErrorCode::kConfiguration, "Wallet name is invalid");
    // Encode every byte, including dots, slashes and percent signs. The name
    // stays one opaque segment; it cannot alter the validated origin or path.
    static constexpr char hex[] = "0123456789ABCDEF";
    resolved.url += "wallet/";
    for (unsigned char byte : *wallet) {
      resolved.url += '%';
      resolved.url += hex[byte >> 4];
      resolved.url += hex[byte & 15];
    }
  }
  Cookie cookie;
  if (!ReadCookie(resolved.cookie_path, &cookie, error)) return false;
  Headers headers;
  Easy easy(curl_easy_init());
  for (const char* value : {"Content-Type: application/json", "Accept-Encoding: identity", "Expect:"}) {
    auto* updated = curl_slist_append(headers.get(), value);
    if (!updated) return Fail(error, BitcoinRpcErrorCode::kConnection, "HTTP initialization failed");
    headers.release();
    headers.reset(updated);
  }
  if (!easy) return Fail(error, BitcoinRpcErrorCode::kConnection, "HTTP initialization failed");
  HttpBuffers buffers;
  // Check every option. Do not expose curl diagnostics: they may contain untrusted text.
  auto option = [&easy](CURLoption key, auto value) {
    return curl_easy_setopt(easy.get(), key, value) == CURLE_OK;
  };
#if LIBCURL_VERSION_NUM >= 0x075500
  const bool protocols = option(CURLOPT_PROTOCOLS_STR, "http") &&
                         option(CURLOPT_REDIR_PROTOCOLS_STR, "http");
#else
  const bool protocols = option(CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP)) &&
                         option(CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP));
#endif
  if (!option(CURLOPT_URL, resolved.url.c_str()) ||
      !protocols ||
      !option(CURLOPT_PROXY, "") || !option(CURLOPT_NOPROXY, "*") ||
      !option(CURLOPT_FOLLOWLOCATION, 0L) || !option(CURLOPT_MAXREDIRS, 0L) ||
      !option(CURLOPT_PATH_AS_IS, 1L) ||
      !option(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED)) ||
      !option(CURLOPT_VERBOSE, 0L) || !option(CURLOPT_NOSIGNAL, 1L) ||
      !option(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_BASIC)) ||
      !option(CURLOPT_USERNAME, cookie.username) ||
      !option(CURLOPT_PASSWORD, cookie.password) ||
      !option(CURLOPT_HTTPHEADER, headers.get()) ||
      !option(CURLOPT_POST, 1L) ||
      !option(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.size())) ||
      !option(CURLOPT_POSTFIELDS, request.data()) ||
      !option(CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(config.connect_timeout.count())) ||
      !option(CURLOPT_TIMEOUT_MS, static_cast<long>((scan ? config.scan_timeout : config.rpc_timeout).count())) ||
      !option(CURLOPT_HTTP_CONTENT_DECODING, 0L) ||
      !option(CURLOPT_WRITEFUNCTION, HttpBodyCallback) ||
      !option(CURLOPT_WRITEDATA, &buffers) ||
      !option(CURLOPT_HEADERFUNCTION, HttpHeaderCallback) ||
      !option(CURLOPT_HEADERDATA, &buffers) ||
      !option(CURLOPT_FRESH_CONNECT, 1L) || !option(CURLOPT_FORBID_REUSE, 1L))
    return Fail(error, BitcoinRpcErrorCode::kConnection, "HTTP configuration failed");
  const CURLcode result = curl_easy_perform(easy.get());
  long status = 0;
  curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE, &status);
  const auto http_status = status >= 100 && status <= 599 ? static_cast<int>(status) : 0;
  if (buffers.too_large)
    return Fail(error, BitcoinRpcErrorCode::kResponseTooLarge, "RPC response exceeds its byte limit", http_status);
  if (buffers.unsupported_encoding)
    return Fail(error, BitcoinRpcErrorCode::kMalformed, "Compressed RPC responses are unsupported", http_status);
  if (buffers.buffer_failure)
    return Fail(error, BitcoinRpcErrorCode::kConnection, "RPC response buffering failed", http_status);
  if (http_status == 401)
    return Fail(error, BitcoinRpcErrorCode::kAuthentication, "RPC cookie authentication failed", http_status);
  if (result == CURLE_OPERATION_TIMEDOUT)
    return Fail(error, BitcoinRpcErrorCode::kTimeout, "RPC request timed out; it was not retried", http_status);
  if (result != CURLE_OK)
    return Fail(error, BitcoinRpcErrorCode::kConnection, "RPC connection failed", http_status);
  char* peer = nullptr;
  if (curl_easy_getinfo(easy.get(), CURLINFO_PRIMARY_IP, &peer) != CURLE_OK ||
      !peer || !IsLoopback(peer))
    return Fail(error, BitcoinRpcErrorCode::kConnection, "RPC connected peer is not loopback", http_status);
  if (http_status < 200 || http_status >= 300) {
    // Private diagnostic channel only: the client can decode a well-formed RPC
    // error, but this HTTP failure can never produce an authorized result.
    *output = {http_status, std::move(buffers.body)};
    return Fail(error, BitcoinRpcErrorCode::kHttp, "RPC HTTP status indicates failure", http_status);
  }
  *output = {http_status, std::move(buffers.body)};
  ClearError(error);
  return true;
}

QuietProofChainEvidence LookupCurrentTip(RpcClient& client,
                                        const QuietProofChainRequest& request) {
  QuietProofChainEvidence evidence;
  auto reject = [&](QuietProofChainStatus status, const char* detail) {
    evidence.status = status;
    evidence.detail = detail;
    return evidence;
  };
  const auto network = client.config().network;
  if (request.has_snapshot || request.network != network ||
      !QuietProofNetworkValid(network))
    return reject(QuietProofChainStatus::kInconclusive, "provider/request mismatch");

  RpcDecodedResponse response;
  BitcoinRpcError error;
  auto call = [&](const char* method, const nlohmann::json& params) {
    return client.Call(method, params, false, &response, &error);
  };
  auto rpc_failure = [&] {
    return reject(error.code == BitcoinRpcErrorCode::kMalformed
                      ? QuietProofChainStatus::kMalformed
                      : QuietProofChainStatus::kUnavailable,
                  "Bitcoin Core RPC request failed");
  };
  if (!call("getblockchaininfo", nlohmann::json::array())) return rpc_failure();
  quietproof_internal::Tip tip;
  if (!quietproof_internal::ParseTipFields(response.result, &tip))
    return reject(QuietProofChainStatus::kMalformed, "getblockchaininfo fields are malformed");
  if (tip.chain != QuietProofBitcoinCoreChainName(network))
    return reject(QuietProofChainStatus::kWrongNetwork, "Bitcoin Core network does not match statement");

  static constexpr char kHex[] = "0123456789abcdef";
  std::string txid;
  txid.reserve(64);
  for (uint8_t byte : request.txid) {
    txid.push_back(kHex[byte >> 4]);
    txid.push_back(kHex[byte & 15]);
  }
  if (!call("gettxout", nlohmann::json::array({txid, request.vout, true})))
    return rpc_failure();
  if (response.result.is_null())
    return reject(QuietProofChainStatus::kInconclusive,
                  "outpoint is absent from the current UTXO set");
  const auto money = response.money.find("/result/value");
  uint64_t amount = 0, confirmations = 0;
  std::vector<uint8_t> script;
  if (money == response.money.end() ||
      !quietproof_internal::ParseTxOutFields(response.result, money->second.token,
          tip.best_block_hash, &amount, &confirmations, &script) ||
      amount == 0 || amount != money->second.sats ||
      script.size() != 22 || script[0] != 0 || script[1] != 20)
    return reject(QuietProofChainStatus::kMalformed, "gettxout fields are not canonical");

  if (!call("getblockchaininfo", nlohmann::json::array())) return rpc_failure();
  quietproof_internal::Tip after;
  if (!quietproof_internal::ParseTipFields(response.result, &after))
    return reject(QuietProofChainStatus::kMalformed, "getblockchaininfo fields are malformed");
  if (after.chain != tip.chain || after.best_block_hash != tip.best_block_hash ||
      after.height != tip.height)
    return reject(QuietProofChainStatus::kInconclusive, "chain tip changed during lookup");

  std::vector<uint8_t> block;
  // ParseTipFields already checked exact lowercase displayed-order hash bytes.
  if (!quietproof_internal::DecodeHex(tip.best_block_hash, &block))
    return reject(QuietProofChainStatus::kMalformed, "best block hash is malformed");
  std::copy(block.begin(), block.end(), evidence.block.begin());
  evidence.network = network;
  evidence.height = tip.height;
  evidence.confirmations = confirmations;
  evidence.amount_sats = amount;
  evidence.script_pub_key = std::move(script);
  evidence.status = QuietProofChainStatus::kUnspent;
  return evidence;
}

namespace {
bool ValidAddressText(const std::string& address) {
  if (address.empty() || address.size() > 90) return false;
  for (unsigned char c : address)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9'))) return false;
  return true;
}
bool HashBytes(const nlohmann::json& value, std::array<uint8_t, 32>* output) {
  if (!value.is_string()) return false;
  const auto text = value.get<std::string>();
  std::vector<uint8_t> bytes;
  if (!quietproof_internal::IsLowerHex(text, 64) ||
      !quietproof_internal::DecodeHex(text, &bytes) ||
      std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; }))
    return false;
  std::copy(bytes.begin(), bytes.end(), output->begin());
  return true;
}
bool P2wpkhScript(const nlohmann::json& value, std::vector<uint8_t>* script) {
  return value.is_string() &&
      quietproof_internal::DecodeHex(value.get<std::string>(), script) &&
      script->size() == 22 && (*script)[0] == 0 && (*script)[1] == 20;
}
}  // namespace

bool DiscoverAddress(RpcClient& client, const BitcoinUtxoQuery& query,
                     BitcoinUtxoDiscovery* output, BitcoinRpcError* error) {
  using namespace quietproof_internal;
  if (!output || query.min_confirmations == 0 ||
      (query.wallet && (query.wallet->empty() || query.wallet->size() > 1024 ||
                        !QuietProofUtf8(*query.wallet) || query.min_confirmations > 9999999)))
    return Fail(error, BitcoinRpcErrorCode::kConfiguration,
                "Discovery requires positive confirmations and a valid explicit wallet when selected");
  if (!ValidAddressText(query.address))
    return Fail(error, BitcoinRpcErrorCode::kInvalidAddress, "Address text is invalid");
  RpcDecodedResponse response;
  if (!client.Call("getblockchaininfo", nlohmann::json::array(), false, &response, error))
    return false;
  Tip tip;
  if (!ParseTipFields(response.result, &tip))
    return Fail(error, BitcoinRpcErrorCode::kMalformed, "Node tip is malformed");
  if (tip.chain != QuietProofBitcoinCoreChainName(client.config().network))
    return Fail(error, BitcoinRpcErrorCode::kWrongNetwork, "Bitcoin Core network does not match discovery");
  if (!client.Call("validateaddress", nlohmann::json::array({query.address}), false,
                   &response, error)) return false;
  const auto& address = response.result;
  if (!address.is_object() || !address.contains("isvalid") || !address["isvalid"].is_boolean())
    return Fail(error, BitcoinRpcErrorCode::kMalformed, "Address validation is malformed");
  if (!address["isvalid"].get<bool>())
    return Fail(error, BitcoinRpcErrorCode::kInvalidAddress, "Address is invalid for the selected node");
  std::vector<uint8_t> script;
  if (!address.contains("scriptPubKey") || !P2wpkhScript(address["scriptPubKey"], &script))
    return Fail(error, BitcoinRpcErrorCode::kUnsupportedScript, "Address must use native P2WPKH");
  if (!address.contains("address") || !address["address"].is_string() ||
      !ValidAddressText(address["address"].get<std::string>()))
    return Fail(error, BitcoinRpcErrorCode::kMalformed, "Canonical address is malformed");
  const std::string canonical = address["address"].get<std::string>();
  BitcoinUtxoDiscovery found;
  found.network = client.config().network;
  const nlohmann::json* candidates = nullptr;
  std::string money_prefix;
  if (query.wallet) {
    // No truncating query options, no spendable filter and no wallet management.
    if (!client.Call("listunspent", nlohmann::json::array({query.min_confirmations,
          9999999, nlohmann::json::array({canonical}), false}), false, &response, error,
          query.wallet)) return false;
    if (!response.result.is_array() || !HashBytes(tip.best_block_hash, &found.observed_block))
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "Wallet UTXO observation is malformed");
    found.observed_height = tip.height;
    candidates = &response.result;
    money_prefix = "/result/";
  } else {
    BitcoinRpcError scan_error;
    if (!client.Call("scantxoutset", nlohmann::json::array({"start",
            nlohmann::json::array({"addr(" + canonical + ")"})}), true, &response, &scan_error)) {
      if (scan_error.code == BitcoinRpcErrorCode::kRpc && scan_error.rpc_code == -8) {
        scan_error.code = BitcoinRpcErrorCode::kScanBusy;
        scan_error.message = "UTXO scan could not start; another scan may be active";
      }
      if (scan_error.code == BitcoinRpcErrorCode::kTimeout)
        scan_error.message = "UTXO scan timed out; it may still be running on Core and was not retried";
      if (error) *error = std::move(scan_error);
      return false;
    }
    const auto& scan = response.result;
    if (!scan.is_object() || !scan.contains("success") || !scan["success"].is_boolean())
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO scan result is malformed");
    if (!scan["success"].get<bool>())
      return Fail(error, BitcoinRpcErrorCode::kScanIncomplete, "UTXO scan did not complete");
    if (!scan.contains("bestblock") || !HashBytes(scan["bestblock"], &found.observed_block) ||
        !scan.contains("height") || !JsonUnsigned(scan["height"], &found.observed_height) ||
        !scan.contains("unspents") || !scan["unspents"].is_array())
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO scan observation is malformed");
    found.scan_block = found.observed_block;
    found.scan_height = found.observed_height;
    candidates = &scan["unspents"];
    money_prefix = "/result/unspents/";
  }
  std::set<std::pair<std::array<uint8_t, 32>, uint32_t>> seen;
  uint64_t total = 0;
  bool valid_total = true;
  for (size_t i = 0; i < candidates->size(); ++i) {
    const auto& candidate = (*candidates)[i];
    BitcoinUtxo coin;
    uint64_t vout = 0, height = 0, reported = 0;
    std::vector<uint8_t> candidate_script;
    const auto money = response.money.find(money_prefix + std::to_string(i) + "/amount");
    if (!candidate.is_object() || !candidate.contains("txid") ||
        !HashBytes(candidate["txid"], &coin.claim.txid) ||
        !candidate.contains("vout") || !JsonUnsigned(candidate["vout"], &vout) ||
        vout > std::numeric_limits<uint32_t>::max() ||
        !candidate.contains("scriptPubKey") ||
        !P2wpkhScript(candidate["scriptPubKey"], &candidate_script) || candidate_script != script ||
        money == response.money.end() || money->second.sats == 0)
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO candidate is malformed");
    coin.claim.vout = static_cast<uint32_t>(vout);
    coin.claim.amount_sats = money->second.sats;
    std::copy(script.begin() + 2, script.end(), coin.claim.program.begin());
    if (query.wallet) {
      if (!candidate.contains("confirmations") || !JsonUnsigned(candidate["confirmations"], &coin.confirmations) ||
          (candidate.contains("address") &&
           (!candidate["address"].is_string() || candidate["address"].get<std::string>() != canonical)))
        return Fail(error, BitcoinRpcErrorCode::kMalformed, "Wallet candidate confirmations or address is malformed");
    } else {
      if (!candidate.contains("height") || !JsonUnsigned(candidate["height"], &height) ||
          height == 0 || height > found.observed_height)
        return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO scan candidate height is malformed");
      coin.confirmations = found.observed_height - height + 1; // height >= 1 prevents overflow.
    }
    if ((candidate.contains("confirmations") &&
         (!JsonUnsigned(candidate["confirmations"], &reported) || reported != coin.confirmations)) ||
        !seen.emplace(coin.claim.txid, coin.claim.vout).second)
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO duplicate or confirmations mismatch");
    if (coin.confirmations < query.min_confirmations) {
      ++found.excluded_below_min_confirmations;
      continue;
    }
    if (coin.claim.amount_sats > kQuietProofMaxMoneySats - total) valid_total = false;
    else total += coin.claim.amount_sats;
    found.outputs.push_back(coin);
  }
  std::sort(found.outputs.begin(), found.outputs.end(), [](const auto& a, const auto& b) {
    return a.claim < b.claim;
  });
  if (found.outputs.empty()) found.incompatibility = "No eligible outputs";
  else if (found.outputs.size() > kQuietProofMaxClaims) found.incompatibility = "Too many outputs for a challenge";
  else if (!valid_total) found.incompatibility = "Aggregate amount exceeds MAX_MONEY";
  else found.challenge_compatible = true;
  if (found.challenge_compatible) {
    bool first = true;
    for (auto& coin : found.outputs) {
      QuietProofChainRequest request{found.network};
      request.txid = coin.claim.txid;
      request.vout = coin.claim.vout;
      const auto evidence = LookupCurrentTip(client, request);
      if (QuietProofMatchClaim(coin.claim, found.network, evidence) != QuietProofChainStatus::kUnspent ||
          evidence.confirmations < query.min_confirmations ||
          std::all_of(evidence.block.begin(), evidence.block.end(), [](uint8_t b) { return b == 0; }) ||
          (!first && (evidence.block != found.observed_block || evidence.height != found.observed_height)))
        return Fail(error, BitcoinRpcErrorCode::kInconclusive, "UTXO current recheck failed or chain tip changed");
      found.observed_block = evidence.block;
      found.observed_height = evidence.height;
      coin.confirmations = evidence.confirmations;
      first = false;
    }
    found.current_rechecked = true;
  }
  *output = std::move(found);
  ClearError(error);
  return true;
}
}  // namespace proofs::bitcoin_rpc_internal

namespace proofs {
class BitcoinCoreRpc::Impl {
 public:
  explicit Impl(BitcoinCoreRpcConfig config) : client_(std::move(config)) {}
  bitcoin_rpc_internal::RpcClient client_;
};
BitcoinCoreRpc::BitcoinCoreRpc(BitcoinCoreRpcConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}
BitcoinCoreRpc::~BitcoinCoreRpc() = default;

bool BitcoinCoreRpc::Discover(const BitcoinUtxoQuery& query, BitcoinUtxoDiscovery* output,
                              BitcoinRpcError* error) {
  try {
    return bitcoin_rpc_internal::DiscoverAddress(impl_->client_, query, output, error);
  } catch (const nlohmann::json::exception&) {
    return bitcoin_rpc_internal::Fail(error, BitcoinRpcErrorCode::kMalformed,
                                     "Discovery response fields are malformed");
  }
}
QuietProofProviderKind BitcoinCoreRpc::kind() const {
  return QuietProofProviderKind::kCurrentTip;
}
QuietProofChainEvidence BitcoinCoreRpc::Lookup(const QuietProofChainRequest& request) {
  return bitcoin_rpc_internal::LookupCurrentTip(impl_->client_, request);
}
}  // namespace proofs
