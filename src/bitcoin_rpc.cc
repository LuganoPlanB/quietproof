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
#include <algorithm>
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
void HttpBuffers::EraseBody() noexcept {
  volatile char* bytes = body.data();
  for (size_t i = 0; i < body.size(); ++i) bytes[i] = 0;
}
HttpBuffers::~HttpBuffers() { EraseBody(); }

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
    if (wallet->size() > 1024 || !QuietProofUtf8(*wallet))
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
    auto* current = headers.release();
    auto* updated = curl_slist_append(current, value);
    if (!updated) {
      headers.reset(current);  // A failed append leaves the existing list intact.
      return Fail(error, BitcoinRpcErrorCode::kConnection, "HTTP initialization failed");
    }
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
  QuietProofScriptKind script_kind;
  std::array<uint8_t, 20> key_hash{};
  if (money == response.money.end() ||
      !quietproof_internal::ParseTxOutFields(response.result, money->second.token,
          tip.best_block_hash, &amount, &confirmations, &script) ||
      amount == 0 || amount != money->second.sats ||
      !QuietProofClassifyScript(script, &script_kind, &key_hash))
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
  QuietProofScriptKind script_kind;
  std::array<uint8_t, 20> key_hash{};
  if (!address.contains("scriptPubKey") || !address["scriptPubKey"].is_string() ||
      !DecodeHex(address["scriptPubKey"].get<std::string>(), &script) ||
      !QuietProofClassifyScript(script, &script_kind, &key_hash))
    return Fail(error, BitcoinRpcErrorCode::kUnsupportedScript,
                "Address must use canonical P2WPKH or P2PKH; proving requires a compressed public key");
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
        !candidate["scriptPubKey"].is_string() ||
        !DecodeHex(candidate["scriptPubKey"].get<std::string>(), &candidate_script) ||
        candidate_script != script ||
        money == response.money.end() || money->second.sats == 0)
      return Fail(error, BitcoinRpcErrorCode::kMalformed, "UTXO candidate is malformed");
    coin.claim.vout = static_cast<uint32_t>(vout);
    coin.claim.amount_sats = money->second.sats;
    coin.claim.script_kind = script_kind;
    coin.claim.program = key_hash;
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
bool ResolveBitcoinRpcSettings(const BitcoinCoreRpcConfig& config,
                               BitcoinRpcSettings* output, BitcoinRpcError* error) {
  bitcoin_rpc_internal::ResolvedRpcConfig resolved;
  if (!output) {
    if (error) *error = {BitcoinRpcErrorCode::kConfiguration,0,std::nullopt,"RPC settings output is required"};
    return false;
  }
  if (!bitcoin_rpc_internal::ResolveRpcConfig(config, &resolved, error)) return false;
  *output = {std::move(resolved.url), std::move(resolved.cookie_path)};
  return true;
}
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
namespace {
// Base58Check encoding of the network byte and public key hash. Decoding and
// validation still belong to Core; this only constructs the export address.
std::string P2pkhAddress(QuietProofNetwork network,
                         const std::array<uint8_t, 20>& program) {
  std::array<uint8_t, 25> payload{};
  payload[0] = network == QuietProofNetwork::kMainnet ? 0 : 111;
  std::copy(program.begin(), program.end(), payload.begin() + 1);
  std::array<uint8_t, 32> digest{};
  SHA256 first;
  first.Update(payload.data(), 21);
  first.DigestData(digest.data());
  SHA256 second;
  second.Update(digest.data(), digest.size());
  second.DigestData(digest.data());
  std::copy_n(digest.begin(), 4, payload.begin() + 21);
  constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::string encoded;
  size_t zeros = 0;
  while (zeros < payload.size() && payload[zeros] == 0) ++zeros;
  for (size_t start = zeros; start < payload.size();) {
    unsigned remainder = 0;
    for (size_t i = start; i < payload.size(); ++i) {
      unsigned value = remainder * 256 + payload[i];
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
// BIP173 witness-v0 encoding: a 20-byte program has exactly 32 base32 digits.
std::string ProgramAddress(QuietProofNetwork network,
                           const std::array<uint8_t, 20>& program) {
  const std::string hrp = network == QuietProofNetwork::kMainnet ? "bc" :
      network == QuietProofNetwork::kRegtest ? "bcrt" : "tb";
  constexpr char alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  constexpr uint32_t generators[] = {
      0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t checksum = 1;
  auto feed = [&](uint8_t value) {
    const uint32_t top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (int i = 0; i < 5; ++i)
      if ((top >> i) & 1) checksum ^= generators[i];
  };
  for (unsigned char c : hrp) feed(c >> 5);
  feed(0);
  for (unsigned char c : hrp) feed(c & 31);
  std::string address = hrp + "1q";
  feed(0);  // Witness version zero uses Bech32, not Bech32m.
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
}  // namespace

bool BitcoinCoreRpc::Probe(const std::optional<BitcoinRpcKeyMatch>& match,
                          BitcoinRpcProbe* output, BitcoinRpcError* error,
                          std::chrono::milliseconds budget) {
  using namespace bitcoin_rpc_internal;
  using namespace quietproof_internal;
  BitcoinRpcError local_error;
  if (!error) error = &local_error;
  if (!output || budget.count() <= 0 || budget.count() > 60000)
    return Fail(error,BitcoinRpcErrorCode::kConfiguration,"Invalid connection test budget or output");
  *output = {};
  if (match && (match->script_kinds.empty() || std::any_of(match->script_kinds.begin(),match->script_kinds.end(),
      [](auto kind) { return kind != QuietProofScriptKind::kP2pkh && kind != QuietProofScriptKind::kP2wpkh; })))
    return Fail(error,BitcoinRpcErrorCode::kUnsupportedScript,"Request script kinds are unsupported");
  const auto deadline = std::chrono::steady_clock::now()+budget;
  RpcDecodedResponse response;
  auto call = [&](const char* method, const nlohmann::json& params,
                  const std::optional<std::string>& wallet = std::nullopt) {
    auto config = impl_->client_.config();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
    if (remaining.count() <= 0) return Fail(error,BitcoinRpcErrorCode::kTimeout,"Connection test time budget expired");
    config.rpc_timeout = std::min(config.rpc_timeout,remaining);
    config.connect_timeout = std::min(config.connect_timeout,remaining);
    // Private sequential clients let remaining time bound the entire probe,
    // including enumeration. Cookies are still reopened for every call.
    RpcClient client(std::move(config));
    return client.Call(method,params,false,&response,error,wallet);
  };
  auto malformed = [&] { return Fail(error,BitcoinRpcErrorCode::kMalformed,"Connection test response is malformed"); };
  try {
    if (!call("getnetworkinfo",nlohmann::json::array())) return false;
    output->authenticated = true;
    uint64_t version = 0;
    if (!response.result.is_object() || !response.result.contains("version") ||
        !JsonUnsigned(response.result["version"],&version)) return malformed();
    output->version = version;
    if (!call("getblockchaininfo",nlohmann::json::array())) return false;
    const auto& chain = response.result;
    if (!chain.is_object() || !chain.contains("chain") || !chain["chain"].is_string() ||
        !chain.contains("initialblockdownload") || !chain["initialblockdownload"].is_boolean()) return malformed();
    const auto chain_name = chain["chain"].get<std::string>();
    if (chain_name != "main" && chain_name != "test" && chain_name != "testnet4" &&
        chain_name != "signet" && chain_name != "regtest") return malformed();
    output->chain = chain_name;
    output->network_matches = chain_name == QuietProofBitcoinCoreChainName(impl_->client_.config().network);
    output->syncing = chain["initialblockdownload"].get<bool>();
    if (!call("help",nlohmann::json::array({"exportaddresskey"}))) {
      if (error->rpc_code != -32601 && error->rpc_code != -8) return false;
      output->export_address_key = false;
      ClearError(error);
    } else {
      if (!response.result.is_string()) return malformed();
      const auto& help = response.result.get_ref<const std::string&>();
      output->export_address_key = help.starts_with("exportaddresskey ") || help.starts_with("exportaddresskey\n");
    }
    if (!call("listwallets",nlohmann::json::array())) return false;
    if (!response.result.is_array() || response.result.size() > 16) return malformed();
    std::set<std::string> names;
    for (const auto& value : response.result) {
      if (!value.is_string()) return malformed();
      auto name = value.get<std::string>();
      if (name.size() > 1024 || !QuietProofUtf8(name) ||
          std::any_of(name.begin(),name.end(),[](unsigned char c) { return c < 32 || c == 127; }) ||
          !names.insert(name).second) return malformed();
      output->wallets.push_back({std::move(name),{}, {}, {}, {}, {}});
    }
    output->wallets_listed = true;
    std::string address;
    if (match && *output->network_matches) {
      const bool p2pkh = std::find(match->script_kinds.begin(),match->script_kinds.end(),QuietProofScriptKind::kP2pkh) != match->script_kinds.end();
      address = p2pkh ? P2pkhAddress(impl_->client_.config().network,match->program) :
                        ProgramAddress(impl_->client_.config().network,match->program);
      if (!call("validateaddress",nlohmann::json::array({address}))) return false;
      const auto& validated = response.result;
      std::vector<uint8_t> script;
      QuietProofScriptKind kind;
      std::array<uint8_t,20> hash{};
      if (!validated.is_object() || !validated.contains("isvalid") || !validated["isvalid"].is_boolean() ||
          !validated["isvalid"].get<bool>() || !validated.contains("scriptPubKey") ||
          !validated["scriptPubKey"].is_string() || !DecodeHex(validated["scriptPubKey"].get<std::string>(),&script) ||
          !QuietProofClassifyScript(script,&kind,&hash) || hash != match->program ||
          std::find(match->script_kinds.begin(),match->script_kinds.end(),kind) == match->script_kinds.end())
        return Fail(error,BitcoinRpcErrorCode::kInvalidAddress,"Node address script does not match the request");
    }
    for (auto& wallet : output->wallets) {
      if (!call("getwalletinfo",nlohmann::json::array(),wallet.name)) {
        wallet.error = *error;
        return false;
      }
      const auto& info = response.result;
      if (!info.is_object() || !info.contains("private_keys_enabled") || !info["private_keys_enabled"].is_boolean() ||
          !info.contains("descriptors") || !info["descriptors"].is_boolean() ||
          !info.contains("external_signer") || !info["external_signer"].is_boolean()) return malformed();
      wallet.private_keys_enabled = info["private_keys_enabled"].get<bool>();
      wallet.descriptor_wallet = info["descriptors"].get<bool>();
      wallet.external_signer = info["external_signer"].get<bool>();
      if (!address.empty()) {
        if (!call("getaddressinfo",nlohmann::json::array({address}),wallet.name)) {
          wallet.error = *error;
          return false;
        }
        const auto& address_info = response.result;
        if (!address_info.is_object() || !address_info.contains("ismine") || !address_info["ismine"].is_boolean() ||
            !address_info.contains("scriptPubKey") || !address_info["scriptPubKey"].is_string() ||
            (address_info.contains("iswatchonly") && !address_info["iswatchonly"].is_boolean())) return malformed();
        std::vector<uint8_t> script;
        QuietProofScriptKind kind;
        std::array<uint8_t,20> hash{};
        if (!DecodeHex(address_info["scriptPubKey"].get<std::string>(),&script) ||
            !QuietProofClassifyScript(script,&kind,&hash)) return malformed();
        wallet.request_matches = address_info["ismine"].get<bool>() &&
            (!address_info.contains("iswatchonly") || !address_info["iswatchonly"].get<bool>()) && hash == match->program &&
            std::find(match->script_kinds.begin(),match->script_kinds.end(),kind) != match->script_kinds.end();
      }
    }
    ClearError(error);
    return true;
  } catch (...) { return malformed(); }
}

bool BitcoinCoreRpc::ExportAddressKey(
    const std::string& requested_wallet, const std::string& requested_address,
    const std::array<uint8_t, 20>& expected_program,
    std::array<uint8_t, 32>* secret, BitcoinRpcError* error) {
  return ExportAddressKey(requested_wallet, requested_address, expected_program,
                          {QuietProofScriptKind::kP2wpkh}, secret, error);
}
bool BitcoinCoreRpc::ExportAddressKey(
    const std::string& requested_wallet, const std::string& requested_address,
    const std::array<uint8_t, 20>& expected_program,
    const std::vector<QuietProofScriptKind>& script_kinds,
    std::array<uint8_t, 32>* secret, BitcoinRpcError* error) {
  return ExportAddressKeyImpl(requested_wallet, requested_address, expected_program,
                             script_kinds, secret, error, true);
}
bool BitcoinCoreRpc::ExportSelectedAddressKey(const std::string& wallet,
    const BitcoinRpcKeyMatch& match, std::array<uint8_t, 32>* secret, BitcoinRpcError* error,
    const std::function<bool()>& stop) {
  return ExportAddressKeyImpl(wallet, {}, match.program, match.script_kinds, secret, error, false, stop);
}
bool BitcoinCoreRpc::ExportAddressKeyImpl(
    const std::string& requested_wallet, const std::string& requested_address,
    const std::array<uint8_t, 20>& expected_program,
    const std::vector<QuietProofScriptKind>& script_kinds,
    std::array<uint8_t, 32>* secret, BitcoinRpcError* error, bool select_sole,
    const std::function<bool()>& stop) {
  using namespace bitcoin_rpc_internal;
  using namespace quietproof_internal;
  auto fail = [&](BitcoinRpcErrorCode code, const char* message) {
    return Fail(error, code, message);
  };
  if (script_kinds.empty() || std::any_of(script_kinds.begin(), script_kinds.end(),
      [](QuietProofScriptKind kind) {
        return kind != QuietProofScriptKind::kP2wpkh && kind != QuietProofScriptKind::kP2pkh;
      })) return fail(BitcoinRpcErrorCode::kConfiguration, "Invalid request script kinds");
  const bool p2pkh = std::find(script_kinds.begin(), script_kinds.end(),
                             QuietProofScriptKind::kP2pkh) != script_kinds.end();
  std::string wallet = requested_wallet;
  const std::string address = requested_address.empty()
      ? (p2pkh ? P2pkhAddress(impl_->client_.config().network, expected_program)
               : ProgramAddress(impl_->client_.config().network, expected_program))
      : requested_address;
  if (!secret || wallet.size() > 1024 ||
      !QuietProofUtf8(wallet) || !ValidAddressText(address))
    return fail(BitcoinRpcErrorCode::kConfiguration, "Invalid wallet or address");
  RpcDecodedResponse response;
  // Erase the returned hex string even when validation fails. JSON/transport
  // libraries may retain copies; this is not a guarantee of complete erasure.
  struct EraseResult {
    nlohmann::json& result;
    ~EraseResult() { EraseRpcJson(result); }
  } erase{response.result};
  try {
    auto& client = impl_->client_;
    auto stopped = [&] {
      if (!stop || !stop()) return false;
      fail(BitcoinRpcErrorCode::kInconclusive,"Address-key export canceled before key access");
      return true;
    };
    if (stopped()) return false;
    if (!client.Call("getblockchaininfo", nlohmann::json::array(), false, &response, error)) return false;
    Tip tip;
    if (!ParseTipFields(response.result, &tip))
      return fail(BitcoinRpcErrorCode::kMalformed, "Node tip is malformed");
    if (tip.chain != QuietProofBitcoinCoreChainName(client.config().network))
      return fail(BitcoinRpcErrorCode::kWrongNetwork, "Bitcoin node network does not match request");
    if (stopped()) return false;
    if (!client.Call("validateaddress", nlohmann::json::array({address}), false, &response, error)) return false;
    const auto& validated = response.result;
    std::vector<uint8_t> script;
    QuietProofScriptKind kind;
    std::array<uint8_t, 20> key_hash{};
    if (!validated.is_object() || !validated.contains("isvalid") ||
        !validated["isvalid"].is_boolean() || !validated["isvalid"].get<bool>() ||
        !validated.contains("scriptPubKey") || !validated["scriptPubKey"].is_string() ||
        !DecodeHex(validated["scriptPubKey"].get<std::string>(), &script) ||
        !QuietProofClassifyScript(script, &kind, &key_hash) ||
        std::find(script_kinds.begin(), script_kinds.end(), kind) == script_kinds.end())
      return fail(BitcoinRpcErrorCode::kUnsupportedScript, "Address script kind does not match the request; no key exported");
    if (key_hash != expected_program)
      return fail(BitcoinRpcErrorCode::kInvalidAddress, "Address does not match the request; no key exported");
    if (stopped()) return false;
    if (wallet.empty() && select_sole) {
      if (!client.Call("listwallets", nlohmann::json::array(), false, &response, error)) return false;
      if (!response.result.is_array())
        return fail(BitcoinRpcErrorCode::kMalformed, "Malformed loaded wallet list");
      if (response.result.size() != 1)
        return fail(BitcoinRpcErrorCode::kConfiguration,
                    "Expected one loaded wallet; load a wallet or select one with --rpc-wallet");
      if (!response.result[0].is_string())
        return fail(BitcoinRpcErrorCode::kMalformed, "Malformed loaded wallet name");
      wallet = response.result[0].get<std::string>();
      if (wallet.size() > 1024 || !QuietProofUtf8(wallet))
        return fail(BitcoinRpcErrorCode::kMalformed, "Invalid loaded wallet name");
    }
    if (!client.Call("exportaddresskey", nlohmann::json::array({address}), false,
                     &response, error, wallet)) {
      if (error && error->rpc_code == -32601)
        error->message = "Node does not support exportaddresskey; use protected stdin mode instead";
      return false;
    }
    const auto& result = response.result;
    if (!result.is_object() || result.size() != 2 ||
        !result.contains("compressed") || !result["compressed"].is_boolean() ||
        !result["compressed"].get<bool>() || !result.contains("private_key_hex") ||
        !result["private_key_hex"].is_string() ||
        !IsLowerHex(result["private_key_hex"].get_ref<const std::string&>(), 64))
      return fail(BitcoinRpcErrorCode::kMalformed, "Invalid address-key export response");
    const auto& hex = result["private_key_hex"].get_ref<const std::string&>();
    for (size_t i = 0; i < secret->size(); ++i)
      (*secret)[i] = (HexNibble(hex[2*i]) << 4) | HexNibble(hex[2*i+1]);
    ClearError(error);
    return true;
  } catch (...) {
    return fail(BitcoinRpcErrorCode::kMalformed, "Address-key export failed; private diagnostics suppressed");
  }
}
bool BitcoinCoreRpc::WalletState(const std::string& wallet,
    BitcoinRpcWalletState* state, BitcoinRpcError* error) {
  using namespace bitcoin_rpc_internal;
  if (!state) return Fail(error, BitcoinRpcErrorCode::kConfiguration, "Missing wallet state output");
  RpcDecodedResponse response;
  if (!impl_->client_.Call("getwalletinfo", nlohmann::json::array(), false, &response, error, wallet)) return false;
  const auto& info = response.result;
  if (!info.is_object()) return Fail(error, BitcoinRpcErrorCode::kMalformed, "Malformed wallet state");
  if (!info.contains("unlocked_until")) { *state = BitcoinRpcWalletState::kUnencrypted; return true; }
  const auto& until = info["unlocked_until"];
  if ((!until.is_number_integer() && !until.is_number_unsigned()) ||
      (until.is_number_integer() && !until.is_number_unsigned() && until.get<int64_t>() < 0))
    return Fail(error, BitcoinRpcErrorCode::kMalformed, "Malformed wallet unlock time");
  *state = until == 0 ? BitcoinRpcWalletState::kLocked : BitcoinRpcWalletState::kUnlocked;
  return true;
}
namespace {
void WalletError(BitcoinRpcError* error) {
  if (!error) return;
  if (error->rpc_code == -14) {
    error->code = BitcoinRpcErrorCode::kWrongPassphrase;
    error->message = "Wallet password rejected. Retry explicitly; no password was saved";
  } else if (error->rpc_code == -13) {
    error->code = BitcoinRpcErrorCode::kWalletLocked;
    error->message = "Wallet is locked. Approve a new attempt explicitly";
  } else if (error->rpc_code == -32601 || error->rpc_code == -15) {
    error->code = BitcoinRpcErrorCode::kUnsupportedWallet;
    error->message = "Wallet unlock operation is unsupported for this wallet";
  }
}
}
bool BitcoinCoreRpc::UnlockWallet(const std::string& wallet, std::span<const char> passphrase,
    std::chrono::seconds lease, BitcoinRpcError* error) {
  using namespace bitcoin_rpc_internal;
  if (passphrase.empty() || passphrase.size() > 1024 || lease.count() < 1 || lease.count() > 30)
    return Fail(error, BitcoinRpcErrorCode::kConfiguration, "Invalid bounded wallet unlock input");
  nlohmann::json params = nlohmann::json::array();
  struct Erase {
    nlohmann::json& params;
    ~Erase() {
      if (!params.empty() && params[0].is_string()) {
        auto& text = params[0].get_ref<std::string&>();
        volatile char* p = text.data();
        for (size_t i = 0; i < text.size(); ++i) p[i] = 0;
      }
    }
  } erase{params};
  try {
    params.push_back("");
    params[0].get_ref<std::string&>().assign(passphrase.data(), passphrase.size());
    params.push_back(lease.count());
    RpcDecodedResponse response;
    struct EraseResponse {
      nlohmann::json& value;
      ~EraseResponse() { EraseRpcJson(value); }
    } erase_response{response.result};
    if (!impl_->client_.Call("walletpassphrase", params, false, &response, error, wallet)) {
      WalletError(error);
      return false;
    }
    if (!response.result.is_null()) return Fail(error, BitcoinRpcErrorCode::kMalformed, "Malformed wallet unlock acknowledgement");
    return true;
  } catch (...) { return Fail(error, BitcoinRpcErrorCode::kConfiguration, "Wallet unlock failed; private diagnostics suppressed"); }
}
bool BitcoinCoreRpc::LockWallet(const std::string& wallet, BitcoinRpcError* error) {
  using namespace bitcoin_rpc_internal;
  RpcDecodedResponse response;
  if (!impl_->client_.Call("walletlock", nlohmann::json::array(), false, &response, error, wallet)) return false;
  if (!response.result.is_null()) return Fail(error, BitcoinRpcErrorCode::kMalformed, "Malformed wallet lock acknowledgement");
  return true;
}
QuietProofProviderKind BitcoinCoreRpc::kind() const {
  return QuietProofProviderKind::kCurrentTip;
}
QuietProofChainEvidence BitcoinCoreRpc::Lookup(const QuietProofChainRequest& request) {
  return bitcoin_rpc_internal::LookupCurrentTip(impl_->client_, request);
}
}  // namespace proofs
