// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include "bitcoin_rpc_internal.h"
#include "bitcoin_rpc_json.h"
#include "quietproof/detail/bitcoin_core_parse.h"
#include "quietproof/bitcoin_core.h"
#include "quietproof/verifier.h"
#include "quietproof/challenge.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace {
using namespace proofs;
using namespace proofs::bitcoin_rpc_internal;
void Require(bool value, const char* label) {
  if (!value) throw std::runtime_error(label);
}
BitcoinCoreRpcConfig Config() {
  BitcoinCoreRpcConfig config{QuietProofNetwork::kRegtest};
  config.rpc_datadir = "/explicit-data";
  return config;
}
void TestConfig() {
  const std::array<const char*, 5> ports{"8332", "18332", "38332", "18443", "48332"};
  const std::array<const char*, 5> paths{".cookie", "testnet3/.cookie", "signet/.cookie",
                                      "regtest/.cookie", "testnet4/.cookie"};
  for (unsigned i = 0; i < ports.size(); ++i) {
    auto config = Config();
    config.network = static_cast<QuietProofNetwork>(i);
    ResolvedRpcConfig result;
    BitcoinRpcError error;
    Require(ResolveRpcConfig(config, &result, &error), "default network config");
    Require(result.url == std::string("http://127.0.0.1:") + ports[i] + "/", "network port");
    Require(result.cookie_path == std::string("/explicit-data/") + paths[i], "network cookie");
    config.rpc_cookie = "/explicit-cookie";
    Require(ResolveRpcConfig(config, &result, &error), "explicit cookie");
    Require(result.cookie_path == config.rpc_cookie, "explicit cookie precedence");
  }
  auto config = Config();
  for (const auto& url : {"http://127.0.0.1/", "http://127.2.3.4:2345/",
                          "http://[::1]:8332/", "http://127.0.0.1"}) {
    config.rpc_url = url;
    ResolvedRpcConfig result;
    Require(ResolveRpcConfig(config, &result, nullptr), "valid literal loopback");
  }
  const std::array bad_urls{
      "http://2130706433/", "http://0x7f000001/", "http://127.1/", "http://0177.0.0.1/",
      "http://127.000.000.001/", "http://localhost/", "http://localhost.localdomain/",
      "http://192.168.0.1/", "http://0.0.0.0/", "http://[::]/", "http://[::ffff:127.0.0.1]/",
      "http://[::1%25lo]/", "https://127.0.0.1/", "file:///etc/passwd", "HTTP://127.0.0.1/",
      "http://u:p@127.0.0.1/", "http://127.0.0.1/?q=1", "http://127.0.0.1/#f",
      "http://127.0.0.1/wallet/a", "http://127.0.0.1/a/../", "http://127.0.0.1//",
      "http://127.0.0.1:0/", "http://127.0.0.1:65536/", "http://127.0.0.1:-1/",
      "http://127.0.0.1:+80/", "http://127.0.0.1:/", "http://127.0.0.1:abc/",
      "http://127.0.0.1\\@192.168.0.1/", "http://127.0.0.1\n/"};
  for (const auto* url : bad_urls) {
    config.rpc_url = url;
    ResolvedRpcConfig output{"sentinel", "sentinel"};
    BitcoinRpcError error;
    Require(!ResolveRpcConfig(config, &output, &error), "invalid URL accepted");
    Require(error.code == BitcoinRpcErrorCode::kConfiguration && output.url == "sentinel",
            "invalid URL changed output or category");
    Require(error.message.find(url) == std::string::npos, "URL leaked in error");
  }
  config.rpc_url = std::string("http://127.0.0.1\0.example/", 26);
  ResolvedRpcConfig output;
  Require(!ResolveRpcConfig(config, &output, nullptr), "NUL URL accepted");
  config = Config();
  config.network = static_cast<QuietProofNetwork>(255);
  Require(!ResolveRpcConfig(config, &output, nullptr), "invalid network");
  for (auto timeout : {std::chrono::milliseconds(0), std::chrono::milliseconds(-1),
                       std::chrono::milliseconds(86400001), std::chrono::milliseconds::max()}) {
    for (unsigned field = 0; field < 3; ++field) {
      config = Config();
      (field == 0 ? config.connect_timeout : field == 1 ? config.rpc_timeout : config.scan_timeout) = timeout;
      Require(!ResolveRpcConfig(config, &output, nullptr), "invalid timeout");
    }
  }
  config = Config();
  config.rpc_timeout = std::chrono::hours(24);
  Require(ResolveRpcConfig(config, &output, nullptr), "maximum timeout");
  const char* current_home = std::getenv("HOME");
  const std::string old_home = current_home ? current_home : "";
  const bool had_home = current_home != nullptr;
  setenv("HOME", "/test-home", 1);
  config = Config();
  config.rpc_datadir.clear();
  Require(ResolveRpcConfig(config, &output, nullptr), "HOME cookie default");
#ifdef __APPLE__
  Require(output.cookie_path == "/test-home/Library/Application Support/Bitcoin/regtest/.cookie", "macOS default");
#else
  Require(output.cookie_path == "/test-home/.bitcoin/regtest/.cookie", "Linux default");
#endif
  unsetenv("HOME");
  Require(!ResolveRpcConfig(config, &output, nullptr), "missing HOME accepted");
  config.rpc_cookie = "/explicit-cookie";
  Require(ResolveRpcConfig(config, &output, nullptr), "explicit cookie without HOME");
  if (had_home) setenv("HOME", old_home.c_str(), 1); else unsetenv("HOME");
}
void TestCallbacks() {
  HttpBuffers buffers;
  std::string body(kMaxBodyBytes, 'a');
  Require(HttpBodyCallback(body.data(), 1, body.size(), &buffers) == body.size(), "body exact limit");
  Require(HttpBodyCallback(body.data(), 1, 1, &buffers) == 0 && buffers.too_large, "body limit");
  buffers = {};
  Require(HttpBodyCallback(nullptr, std::numeric_limits<std::size_t>::max(), 2, &buffers) == 0 &&
          buffers.too_large, "body multiplication overflow");
  buffers = {};
  Require(HttpHeaderCallback(nullptr, std::numeric_limits<std::size_t>::max(), 2, &buffers) == 0 &&
          buffers.too_large, "header multiplication overflow");
  buffers = {};
  std::string header(kMaxHeaderBytes, 'a');
  Require(HttpHeaderCallback(header.data(), 1, header.size(), &buffers) == header.size(), "header exact limit");
  Require(HttpHeaderCallback(header.data(), 1, 1, &buffers) == 0 && buffers.too_large, "header limit");
}
void WriteCookie(const std::filesystem::path& path, const std::string& content, mode_t mode = 0600) {
  std::ofstream stream(path, std::ios::binary);
  stream.write(content.data(), static_cast<std::streamsize>(content.size()));
  stream.close();
  Require(chmod(path.c_str(), mode) == 0, "cookie chmod");
}
void TestCookies() {
  Require(SecureCookieMetadata(S_IFREG | 0600, 123, 123), "secure cookie metadata");
  Require(!SecureCookieMetadata(S_IFREG | 0600, 124, 123), "foreign-owner cookie metadata");
  Require(!SecureCookieMetadata(S_IFREG | 0640, 123, 123), "group-readable cookie metadata");
  Require(!SecureCookieMetadata(S_IFIFO | 0600, 123, 123), "non-regular cookie metadata");
  std::array<char, 40> pattern{};
  const std::string initial = "/tmp/quietproof-cookie-XXXXXX";
  std::copy(initial.begin(), initial.end(), pattern.begin());
  Require(mkdtemp(pattern.data()) != nullptr, "cookie test directory");
  const std::filesystem::path dir(pattern.data());
  struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{dir};
  auto config = Config();
  const int refused = socket(AF_INET, SOCK_STREAM, 0);
  Require(refused >= 0, "cookie test socket");
  struct CloseSocket { int fd; ~CloseSocket() { close(fd); } } close_socket{refused};
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  Require(bind(refused, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "reserve refused port");
  socklen_t address_size = sizeof(address);
  Require(getsockname(refused, reinterpret_cast<sockaddr*>(&address), &address_size) == 0, "read refused port");
  config.rpc_url = "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/";
  config.rpc_cookie = (dir / "cookie").string();
  config.connect_timeout = std::chrono::milliseconds(50);
  config.rpc_timeout = std::chrono::milliseconds(50);
  auto reject = [&] {
    HttpResponse response{777, "unchanged"};
    BitcoinRpcError error;
    Require(!PostRpcHttp(config, "{}", false, &response, &error), "invalid cookie accepted");
    Require(error.code == BitcoinRpcErrorCode::kCookie, "invalid cookie category");
    Require(response.status == 777 && response.body == "unchanged", "cookie error changed output");
    Require(error.message.find("secret") == std::string::npos, "cookie leaked");
  };
  reject();  // Missing.
  for (const auto& content : {std::string(), std::string("username"), std::string(":secret"),
       std::string("user:"), std::string("user:secret\n\n"), std::string("user:sec\rret"),
       std::string("user:sec\tret"), std::string("user:sec\0ret", 12),
       std::string("user:sec\177ret"), std::string("user:sec\200ret"),
       std::string(kMaxCookieBytes + 1, 's')}) {
    WriteCookie(config.rpc_cookie, content);
    reject();
  }
  for (mode_t mode : {0644, 0640, 0604, 0660}) {
    WriteCookie(config.rpc_cookie, "user:secret", mode);
    reject();
  }
  std::filesystem::remove(config.rpc_cookie);
  WriteCookie(dir / "other", "user:secret");
  std::filesystem::create_symlink(dir / "other", config.rpc_cookie);
  reject();
  std::filesystem::remove(config.rpc_cookie);
  Require(mkfifo(config.rpc_cookie.c_str(), 0600) == 0, "cookie FIFO creation");
  const auto start = std::chrono::steady_clock::now();
  reject();
  Require(std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "FIFO cookie blocked");
  std::filesystem::remove(config.rpc_cookie);
  std::filesystem::create_directory(config.rpc_cookie);
  reject();
  std::filesystem::remove(config.rpc_cookie);
  for (const auto& content : {std::string("user:secret\n"), std::string("user:secret:with:colons"),
                             std::string("user:") + std::string(kMaxCookieBytes - 5, 's')}) {
    WriteCookie(config.rpc_cookie, content);
    HttpResponse response;
    BitcoinRpcError error;
    Require(!PostRpcHttp(config, "{}", false, &response, &error) &&
            error.code == BitcoinRpcErrorCode::kConnection, "valid cookie rejected before connect");
  }
}
std::string Envelope(const std::string& result, const std::string& id = "fixture") {
  return "{\"jsonrpc\":\"2.0\",\"id\":\"" + id + "\",\"result\":" + result + "}";
}
RpcDecodedResponse Decode(const std::string& body, int status = 200) {
  RpcDecodedResponse decoded;
  BitcoinRpcError error{BitcoinRpcErrorCode::kCookie, 123, 42, "old"};
  Require(DecodeRpcResponse({status, body}, "fixture", &decoded, &error), "valid RPC response rejected");
  Require(error.code == BitcoinRpcErrorCode::kNone && error.http_status == 0 &&
          !error.rpc_code && error.message.empty(), "decoder success did not clear error");
  return decoded;
}
void RejectJson(const std::string& body, BitcoinRpcErrorCode expected = BitcoinRpcErrorCode::kMalformed,
                int status = 200, std::optional<int64_t> rpc_code = std::nullopt) {
  RpcDecodedResponse output;
  output.result = {{"sentinel", true}};
  output.money["sentinel"] = {"raw", 42};
  BitcoinRpcError error;
  Require(!DecodeRpcResponse({status, body}, "fixture", &output, &error), "invalid RPC response accepted");
  Require(output.result == nlohmann::json({{"sentinel", true}}) &&
          output.money.size() == 1 && output.money.at("sentinel").sats == 42,
          "decoder failure changed output");
  Require(error.code == expected && error.http_status == status && error.rpc_code == rpc_code,
          "decoder failure category/status/code");
  Require(error.message.size() < 128 && error.message.find("server-secret") == std::string::npos,
          "decoder leaked server error");
}
void TestEnvelopes() {
  Require(Decode(Envelope("null")).result.is_null(), "legitimate null result");
  Require(Decode(Envelope("{\"ok\":true}")).result["ok"] == true, "object result");
  for (const auto* body : {"", "null", "[]", "[{}]", "true", "{}",
       R"({"jsonrpc":"1.0","id":"fixture","result":null})",
       R"({"jsonrpc":2.0,"id":"fixture","result":null})",
       R"({"jsonrpc":"2.0","result":null})",
       R"({"jsonrpc":"2.0","id":null,"result":null})",
       R"({"jsonrpc":"2.0","id":1,"result":null})",
       R"({"jsonrpc":"2.0","id":"other","result":null})",
       R"({"jsonrpc":"2.0","id":"fixture"})",
       R"({"jsonrpc":"2.0","id":"fixture","result":null,"error":null})",
       R"({"jsonrpc":"2.0","id":"fixture","error":null})",
       R"({"jsonrpc":"2.0","id":"fixture","error":{"code":-1}})",
       R"({"jsonrpc":"2.0","id":"fixture","error":{"code":-1,"message":4}})",
       R"({"jsonrpc":"2.0","id":"fixture","error":{"code":-1.0,"message":"x"}})",
       R"({"jsonrpc":"2.0","id":"fixture","error":{"code":9223372036854775808,"message":"x"}})",
       R"({"jsonrpc":"2.0","id":"fixture","error":{"code":-9223372036854775809,"message":"x"}})",
       R"({"jsonrpc":"2.0","id":"fixture","id":"fixture","result":null})",
       R"({"jsonrpc":"2.0","id":"fixture","result":{"x":1,"x":2}})",
       R"({"jsonrpc":"2.0","id":"fixture","result":{"x":1,"\u0078":2}})",
       R"({"jsonrpc":"2.0","id":"fixture","result":{"a/b":1,"a\u002fb":2}})",
       R"({"jsonrpc":"2.0","id":"fixture","result":1e999})",
       R"({"jsonrpc":"2.0","id":"fixture","result":null} true)",
       R"({"jsonrpc":"2.0","id":"fixture","result":null,})",
       R"({/*comment*/"jsonrpc":"2.0","id":"fixture","result":null})"}) RejectJson(body);
  RejectJson(Envelope("\"" + std::string(1, static_cast<char>(0xff)) + "\""));
  RejectJson(Envelope("null") + std::string("\0x", 2));
  const auto good = Envelope("{\"value\":0.00000001}");
  for (std::size_t i = 0; i < good.size(); ++i) RejectJson(good.substr(0, i));
  Decode(Envelope(std::string(63, '[') + "0" + std::string(63, ']')));
  RejectJson(Envelope(std::string(64, '[') + "0" + std::string(64, ']')));
  auto maximum = Envelope("null");
  maximum.append(kMaxBodyBytes - maximum.size(), ' ');
  Decode(maximum);
  maximum += ' ';
  RejectJson(maximum, BitcoinRpcErrorCode::kResponseTooLarge);
  for (const auto& code : {std::string("-8"), std::string("9223372036854775807"),
                            std::string("-9223372036854775808"), std::string("0")}) {
    const auto body = "{\"jsonrpc\":\"2.0\",\"id\":\"fixture\",\"error\":{\"code\":" + code +
        ",\"message\":\"server-secret\"}}";
    const auto value = std::stoll(code);
    RejectJson(body, BitcoinRpcErrorCode::kRpc, 200, value);
    RejectJson(body, BitcoinRpcErrorCode::kRpc, 500, value);
  }
  auto error = nlohmann::json{{"jsonrpc", "2.0"}, {"id", "fixture"},
      {"error", {{"code", -1}, {"message", std::string(kMaxRpcErrorMessageBytes, 'x')}}}};
  RejectJson(error.dump(), BitcoinRpcErrorCode::kRpc, 200, -1);
  error["error"]["message"] = std::string(kMaxRpcErrorMessageBytes + 1, 'x');
  RejectJson(error.dump());
  RejectJson(Envelope("null"), BitcoinRpcErrorCode::kHttp, 500);
  RejectJson("server-secret", BitcoinRpcErrorCode::kHttp, 500);
  RejectJson(Envelope("null"), BitcoinRpcErrorCode::kAuthentication, 401);
}
void TestExactMoney() {
  const std::array<std::pair<const char*, uint64_t>, 6> valid{{
      {"0.00000001", 1}, {"0.1", 10000000}, {"1", 100000000},
      {"0.12345678", 12345678}, {"20999999.99999999", 2099999999999999ULL},
      {"21000000.00000000", 2100000000000000ULL}}};
  for (const auto& [token, sats] : valid) {
    const std::array<std::pair<std::string, std::string>, 3> shapes{{
        {"{\"value\":" + std::string(token) + "}", "/result/value"},
        {"{\"unspents\":[{\"amount\":" + std::string(token) + "}]}", "/result/unspents/0/amount"},
        {"[{\"amount\":" + std::string(token) + "}]", "/result/0/amount"}}};
    for (const auto& [result, path] : shapes) {
      const auto decoded = Decode(Envelope(result));
      Require(decoded.money.size() == 1 && decoded.money.at(path).token == token &&
              decoded.money.at(path).sats == sats, "original money lexeme or exact sats changed");
      // Floating-point data is deliberately absent from monetary DOM nodes.
      auto relative = path.substr(std::string("/result").size());
      Require(decoded.result.at(nlohmann::json::json_pointer(relative)).is_null(), "money used floating DOM");
    }
  }
  for (const auto* token : {"0", "-1", "-0.00000001", "21000000.00000001", "21000001",
       "0.000000001", "0.100000000", "1e-8", "1E0", "1.0e0", "18446744073709551616",
       "99999999999999999999999999999999", "\"0.1\"", "null", "true", "{}", "[]"}) {
    RejectJson(Envelope("{\"value\":" + std::string(token) + "}"));
    RejectJson(Envelope("{\"unspents\":[{\"amount\":" + std::string(token) + "}]}"));
    RejectJson(Envelope("[{\"amount\":" + std::string(token) + "}]"));
  }
  const auto unrelated = Decode(Envelope(
      R"({"nested":{"value":1e-9},"amount":"ignored","unspents":{"0":{"amount":"ignored"}},"value~":"ignored","a/b":{"value":"ignored"}})"));
  Require(unrelated.money.empty(), "unrelated object key substituted for money");
  const auto escaped = Decode(Envelope(R"({"\u0076alue":0.00000001})"));
  Require(escaped.money.at("/result/value").sats == 1, "escaped actual value key ignored");
  const auto arrays = Decode(Envelope(R"({"unspents":[{"other":{"amount":"ignored"},"amount":0.1},{"amount":0.2}]})"));
  Require(arrays.money.size() == 2 && arrays.money.at("/result/unspents/1/amount").sats == 20000000,
          "array index money path");
}
struct MockState {
  std::vector<nlohmann::json> requests;
  int status = 200;
  bool fail = false;
  bool bad_id = false;
  bool rpc_error = false;
  bool scan = false;
} mock;
bool MockHttp(const BitcoinCoreRpcConfig&, const std::string& request, bool scan,
              HttpResponse* response, BitcoinRpcError* error, const std::optional<std::string>& wallet) {
  Require(!wallet, "ordinary request used wallet route");
  const auto parsed = nlohmann::json::parse(request);
  mock.requests.push_back(parsed);
  mock.scan = scan;
  if (mock.fail) {
    if (error) *error = {BitcoinRpcErrorCode::kTimeout, 0, std::nullopt, "RPC request timed out"};
    return false;
  }
  nlohmann::json envelope{{"jsonrpc", "2.0"}, {"id", mock.bad_id ? nlohmann::json("other") : parsed["id"]}};
  if (mock.rpc_error) envelope["error"] = {{"code", -8}, {"message", "server-secret"}};
  else envelope["result"] = nullptr;
  *response = {mock.status, envelope.dump()};
  if (mock.status >= 300) {
    if (error) *error = {BitcoinRpcErrorCode::kHttp, mock.status, std::nullopt, "RPC HTTP status indicates failure"};
    return false;
  }
  return true;
}
void TestRequests() {
  mock = {};
  RpcClient client(Config(), MockHttp);
  RpcDecodedResponse response;
  BitcoinRpcError error;
  const std::string input = "quoted\"\\\ntext";
  Require(client.Call("fixture", nlohmann::json::array({input}), false, &response, &error), "request serializer");
  Require(mock.requests[0]["params"][0] == input && mock.requests[0]["id"] == "1" &&
          mock.requests[0]["jsonrpc"] == "2.0", "request serialized wrong values or types");
  mock.fail = true;
  Require(!client.Call("fixture", nlohmann::json::array(), true, &response, &error) &&
          error.code == BitcoinRpcErrorCode::kTimeout && mock.scan, "transport failure mapping");
  mock.fail = false;
  Require(client.Call("fixture", nlohmann::json::array(), false, &response, &error), "request after failure");
  Require(mock.requests[1]["id"] == "2" && mock.requests[2]["id"] == "3", "ID reused after failure");
  mock.bad_id = true;
  Require(!client.Call("fixture", nlohmann::json::array(), false, &response, &error) &&
          error.code == BitcoinRpcErrorCode::kMalformed, "client accepted wrong ID");
  mock.bad_id = false;
  mock.rpc_error = true;
  for (int status : {200, 500}) {
    mock.status = status;
    Require(!client.Call("fixture", nlohmann::json::array(), false, &response, &error) &&
            error.code == BitcoinRpcErrorCode::kRpc && error.rpc_code == -8 && error.http_status == status,
            "client lost RPC error diagnostics");
  }
  mock.rpc_error = false;
  mock.status = 500;
  Require(!client.Call("fixture", nlohmann::json::array(), false, &response, &error) &&
          error.code == BitcoinRpcErrorCode::kHttp, "non2xx authorized result");
  const auto count = mock.requests.size();
  Require(!client.Call("fixture", nlohmann::json::object(), false, &response, &error) &&
          mock.requests.size() == count, "non-array params sent");
  Require(!client.Call("fixture", nlohmann::json::array({std::string(1, static_cast<char>(0xff))}),
                       false, &response, &error) &&
          error.code == BitcoinRpcErrorCode::kConfiguration && mock.requests.size() == count,
          "request JSON exception escaped or sent invalid UTF8");
  RpcClient independent(Config(), MockHttp);
  mock.status = 200;
  Require(independent.Call("fixture", nlohmann::json::array(), false, &response, &error) &&
          mock.requests.back()["id"] == "1", "IDs not owned per client");
}

struct LookupFixture {
  std::vector<std::string> results;
  std::vector<nlohmann::json> requests;
  size_t fail_at = std::numeric_limits<size_t>::max();
  BitcoinRpcErrorCode failure = BitcoinRpcErrorCode::kTimeout;
  int http_status = 200;
  bool rpc_error = false;
} lookup_fixture;
const std::string kLookupBlock = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
std::string LookupTip(const std::string& chain = "regtest",
                      const std::string& block = kLookupBlock, uint64_t height = 100) {
  return nlohmann::json{{"chain", chain}, {"bestblockhash", block}, {"blocks", height}}.dump();
}
std::string LookupTxOut(const std::string& amount = "0.00000001",
                       const std::string& confirmations = "2",
                       const std::string& script = "0014" + std::string(40, 'a'),
                       const std::string& block = kLookupBlock) {
  return "{\"bestblock\":\"" + block + "\",\"confirmations\":" + confirmations +
      ",\"value\":" + amount + ",\"scriptPubKey\":{\"hex\":\"" + script + "\"}}";
}
bool LookupHttp(const BitcoinCoreRpcConfig&, const std::string& text, bool scan,
                HttpResponse* response, BitcoinRpcError* error, const std::optional<std::string>& wallet) {
  Require(!wallet, "lookup used wallet route");
  Require(!scan, "lookup used scan deadline");
  auto request = nlohmann::json::parse(text);
  const size_t index = lookup_fixture.requests.size();
  lookup_fixture.requests.push_back(request);
  if (index == lookup_fixture.fail_at) {
    if (error) *error = {lookup_fixture.failure, 0, std::nullopt, "redacted fixture failure"};
    return false;
  }
  Require(index < lookup_fixture.results.size(), "unexpected lookup RPC");
  response->status = lookup_fixture.http_status;
  response->body = "{\"jsonrpc\":\"2.0\",\"id\":" + request["id"].dump() +
      (lookup_fixture.rpc_error ? ",\"error\":{\"code\":-8,\"message\":\"server-secret\"}}" :
       ",\"result\":" + lookup_fixture.results[index] + "}");
  if (response->status >= 300) {
    if (error) *error = {BitcoinRpcErrorCode::kHttp, response->status, std::nullopt, "HTTP failure"};
    return false;
  }
  return true;
}
const std::string kDiscoveryAddress = "bcrt1qfixture";
const std::string kDiscoveryScript = "0014" + std::string(40, 'a');
struct DiscoveryFixture {
  std::string validation = nlohmann::json{{"isvalid", true}, {"address", kDiscoveryAddress},
                                        {"scriptPubKey", kDiscoveryScript}}.dump();
  std::string scan;
  std::string chain = "regtest";
  std::string recheck_block = kLookupBlock;
  std::string txout = LookupTxOut();
  std::vector<nlohmann::json> requests;
  bool busy = false;
  bool timeout = false;
  bool split_tip = false;
  size_t rechecks = 0;
} discovery_fixture;
std::string ScanCoin(unsigned index, const std::string& amount = "0.00000001",
                     uint64_t height = 99) {
  return "{\"txid\":\"" + std::string(62, '1') + "0123456789abcdef"[index / 16] +
      "0123456789abcdef"[index % 16] + "\",\"vout\":0,\"height\":" + std::to_string(height) +
      ",\"scriptPubKey\":\"" + kDiscoveryScript + "\",\"amount\":" + amount + "}";
}
std::string ScanResult(const std::vector<std::string>& coins) {
  std::string result = "{\"success\":true,\"height\":100,\"bestblock\":\"" + kLookupBlock +
      "\",\"unspents\":[";
  for (size_t i = 0; i < coins.size(); ++i) result += (i ? "," : "") + coins[i];
  return result + "]}";
}
bool DiscoveryHttp(const BitcoinCoreRpcConfig&, const std::string& text, bool scan,
                   HttpResponse* response, BitcoinRpcError* error, const std::optional<std::string>& wallet) {
  Require(!wallet, "scan used wallet route");
  auto request = nlohmann::json::parse(text);
  discovery_fixture.requests.push_back(request);
  const auto method = request["method"].get<std::string>();
  Require(scan == (method == "scantxoutset"), "discovery wrong deadline");
  std::string result;
  if (method == "getblockchaininfo") {
    const bool initial = discovery_fixture.requests.size() == 1;
    auto block = initial ? kLookupBlock : discovery_fixture.recheck_block;
    if (!initial && discovery_fixture.split_tip && discovery_fixture.rechecks >= 2)
      block = std::string(64, 'f');
    result = LookupTip(discovery_fixture.chain, block, initial ? 100 : 101);
  } else if (method == "validateaddress") {
    Require(request["params"] == nlohmann::json::array({kDiscoveryAddress}), "validate address params");
    result = discovery_fixture.validation;
  } else if (method == "scantxoutset") {
    Require(request["params"] == nlohmann::json::array({"start", nlohmann::json::array({"addr(" + kDiscoveryAddress + ")"})}),
            "single internal addr descriptor");
    if (discovery_fixture.timeout) {
      if (error) *error = {BitcoinRpcErrorCode::kTimeout, 0, std::nullopt, "fixture"};
      return false;
    }
    result = discovery_fixture.scan;
  } else {
    Require(method == "gettxout" && request["params"][2] == true, "discovery recheck method");
    ++discovery_fixture.rechecks;
    result = discovery_fixture.txout;
  }
  response->status = 200;
  response->body = "{\"jsonrpc\":\"2.0\",\"id\":" + request["id"].dump() +
      (method == "scantxoutset" && discovery_fixture.busy ?
       ",\"error\":{\"code\":-8,\"message\":\"server-secret\"}}" : ",\"result\":" + result + "}");
  return true;
}
void TestDiscovery() {
  size_t cases = 0;
  BitcoinUtxoQuery query{kDiscoveryAddress};
  auto reset = [&] {
    discovery_fixture = {};
    discovery_fixture.scan = ScanResult({ScanCoin(1)});
    query = BitcoinUtxoQuery{kDiscoveryAddress};
  };
  auto run = [&](BitcoinRpcErrorCode expected, size_t calls) {
    RpcClient client(Config(), DiscoveryHttp);
    BitcoinUtxoDiscovery output;
    output.incompatibility = "sentinel";
    BitcoinRpcError error;
    const bool ok = DiscoverAddress(client, query, &output, &error);
    Require(ok == (expected == BitcoinRpcErrorCode::kNone), "discovery result category");
    Require(error.code == expected && discovery_fixture.requests.size() == calls, "discovery error/call count");
    if (!ok) Require(output.incompatibility == "sentinel", "discovery failure changed output");
    Require(error.message.find("server-secret") == std::string::npos, "discovery leaked server message");
    ++cases;
    return output;
  };
  for (const auto& invalid : {"", "a b", "addr(x)", "a,b", "a#b", "a[b]", "a{b}"}) {
    reset(); query.address = invalid; run(BitcoinRpcErrorCode::kInvalidAddress, 0);
  }
  reset(); query.address = std::string(91, 'a'); run(BitcoinRpcErrorCode::kInvalidAddress, 0);
  reset(); query.min_confirmations = 0; run(BitcoinRpcErrorCode::kConfiguration, 0);
  reset(); discovery_fixture.chain = "main"; run(BitcoinRpcErrorCode::kWrongNetwork, 1);
  reset(); discovery_fixture.validation = R"({"isvalid":false})"; run(BitcoinRpcErrorCode::kInvalidAddress, 2);
  reset(); discovery_fixture.validation = R"({"isvalid":1})"; run(BitcoinRpcErrorCode::kMalformed, 2);
  for (auto script : {"a914" + std::string(40, 'a') + "87", "0020" + std::string(64, 'a'),
                      "5120" + std::string(64, 'a'), kDiscoveryScript + "00", "0014" + std::string(40, 'A')}) {
    reset(); discovery_fixture.validation = nlohmann::json{{"isvalid", true}, {"address", kDiscoveryAddress}, {"scriptPubKey", script}}.dump();
    run(BitcoinRpcErrorCode::kUnsupportedScript, 2);
  }
  reset(); discovery_fixture.scan = ScanResult({});
  auto found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(found.outputs.empty() && !found.challenge_compatible && !found.current_rechecked, "empty discovery flags");
  reset(); discovery_fixture.busy = true; run(BitcoinRpcErrorCode::kScanBusy, 3);
  reset(); discovery_fixture.timeout = true; run(BitcoinRpcErrorCode::kTimeout, 3);
  reset(); discovery_fixture.scan = R"({"success":false})"; run(BitcoinRpcErrorCode::kScanIncomplete, 3);
  reset(); discovery_fixture.scan = R"({"success":true})"; run(BitcoinRpcErrorCode::kMalformed, 3);
  for (const auto& patch : {nlohmann::json{{"height", -1}}, nlohmann::json{{"height", "100"}},
                           nlohmann::json{{"bestblock", std::string(64, '0')}},
                           nlohmann::json{{"unspents", nullptr}}, nlohmann::json{{"success", 1}}}) {
    reset(); auto scan = nlohmann::json::parse(ScanResult({})); scan.update(patch);
    discovery_fixture.scan = scan.dump(); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (auto amount : {"0", "-1", "1e-8", "0.000000001", "21000000.00000001", "18446744073709551616", "\"0.1\""}) {
    reset(); discovery_fixture.scan = ScanResult({ScanCoin(1, amount)}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (uint64_t height : {uint64_t{0}, uint64_t{101}, std::numeric_limits<uint64_t>::max()}) {
    reset(); discovery_fixture.scan = ScanResult({ScanCoin(1, "1", height)}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (const auto& field : {"txid", "vout", "height", "scriptPubKey"}) {
    reset(); auto coin = nlohmann::json::parse(ScanCoin(1, "1")); coin.erase(field);
    discovery_fixture.scan = ScanResult({coin.dump()}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (const auto& patch : {nlohmann::json{{"vout", 4294967296ULL}}, nlohmann::json{{"vout", -1}},
                           nlohmann::json{{"txid", std::string(64, '0')}}, nlohmann::json{{"confirmations", 3}},
                           nlohmann::json{{"scriptPubKey", "0014" + std::string(40, 'b')}}}) {
    reset(); auto coin = nlohmann::json::parse(ScanCoin(1, "1")); coin.update(patch);
    discovery_fixture.scan = ScanResult({coin.dump()}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  reset(); discovery_fixture.scan = ScanResult({ScanCoin(1), ScanCoin(1)}); run(BitcoinRpcErrorCode::kMalformed, 3);
  reset(); query.min_confirmations = 3;
  discovery_fixture.scan = ScanResult({ScanCoin(1), ScanCoin(1, "1", 100)}); // Duplicates rejected even below policy.
  run(BitcoinRpcErrorCode::kMalformed, 3);
  reset(); query.min_confirmations = 3;
  found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(found.excluded_below_min_confirmations == 1 && found.outputs.empty(), "confirmation exclusion count");
  reset(); discovery_fixture.scan = ScanResult({ScanCoin(2), ScanCoin(1)});
  found = run(BitcoinRpcErrorCode::kNone, 9);
  Require(found.outputs.size() == 2 && found.outputs[0].claim < found.outputs[1].claim &&
          found.current_rechecked && found.challenge_compatible && found.observed_height == 101 &&
          found.scan_height == 100, "sorted/current discovery observation");
  std::vector<QuietProofClaimV1> claims;
  for (const auto& coin : found.outputs) claims.push_back(coin.claim);
  QuietProofStatementV1 statement;
  QuietProofChallengeOptions options{QuietProofNetwork::kRegtest, "verifier", "proof-of-funds", "message"};
  Require(CreateQuietProofChallenge(claims, options, &statement) && !statement.has_snapshot,
          "discovery cannot feed challenge builder");
  reset(); discovery_fixture.txout = LookupTxOut("0.00000001", "2", "0014" + std::string(40, 'b'));
  run(BitcoinRpcErrorCode::kInconclusive, 6);
  reset(); discovery_fixture.txout = "null"; run(BitcoinRpcErrorCode::kInconclusive, 5);
  reset(); discovery_fixture.txout = LookupTxOut("0.1"); run(BitcoinRpcErrorCode::kInconclusive, 6);
  reset(); query.min_confirmations = 3; discovery_fixture.scan = ScanResult({ScanCoin(1, "0.00000001", 98)});
  run(BitcoinRpcErrorCode::kInconclusive, 6);
  reset(); discovery_fixture.scan = ScanResult({ScanCoin(1), ScanCoin(2)}); discovery_fixture.split_tip = true;
  run(BitcoinRpcErrorCode::kInconclusive, 9);
  reset(); discovery_fixture.recheck_block = std::string(64, 'f');
  discovery_fixture.txout = LookupTxOut("0.00000001", "2", kDiscoveryScript, discovery_fixture.recheck_block);
  found = run(BitcoinRpcErrorCode::kNone, 6);
  Require(found.observed_block != *found.scan_block, "tip advance discarded scan observation");
  for (unsigned count : {16, 17}) {
    reset(); std::vector<std::string> coins;
    for (unsigned i = count; i > 0; --i) coins.push_back(ScanCoin(i));
    discovery_fixture.scan = ScanResult(coins);
    found = run(BitcoinRpcErrorCode::kNone, count == 16 ? 51 : 3);
    Require(found.outputs.size() == count && found.challenge_compatible == (count == 16) &&
            found.current_rechecked == (count == 16), "output count silently truncated");
    claims.clear(); for (const auto& coin : found.outputs) claims.push_back(coin.claim);
    Require(CreateQuietProofChallenge(claims, options, &statement) == (count == 16), "builder excessive set contract");
  }
  reset(); auto boundary = nlohmann::json::parse(ScanCoin(1, "1")); boundary["vout"] = 4294967295ULL;
  discovery_fixture.scan = ScanResult({boundary.dump()}); discovery_fixture.txout = LookupTxOut("1");
  found = run(BitcoinRpcErrorCode::kNone, 6);
  Require(found.outputs[0].claim.vout == 4294967295ULL, "u32 vout boundary rejected");
  for (auto amount : {"0.1", "20999999.99999999", "21000000"}) {
    reset(); discovery_fixture.scan = ScanResult({ScanCoin(1, amount)});
    discovery_fixture.txout = LookupTxOut(amount);
    found = run(BitcoinRpcErrorCode::kNone, 6);
    uint64_t sats = 0;
    Require(quietproof_internal::BitcoinAmountToSats(amount, &sats) && found.outputs[0].claim.amount_sats == sats,
            "scan original decimal amount changed");
  }
  reset(); query.min_confirmations = 2;
  discovery_fixture.scan = ScanResult({ScanCoin(1), ScanCoin(2, "0.00000001", 100)});
  found = run(BitcoinRpcErrorCode::kNone, 6);
  Require(found.outputs.size() == 1 && found.excluded_below_min_confirmations == 1, "mixed confirmation filtering");
  reset(); discovery_fixture.scan = ScanResult({ScanCoin(1, "21000000"), ScanCoin(2, "0.00000001")});
  found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(!found.challenge_compatible && !found.current_rechecked && found.outputs.size() == 2, "sum bound compatibility");
  claims.clear(); for (const auto& coin : found.outputs) claims.push_back(coin.claim);
  Require(!CreateQuietProofChallenge(claims, options, &statement), "aggregate-overflow set built challenge");
  std::cout << "Scan discovery cases passed: " << cases << '\n';
}

struct WalletFixture {
  std::string result;
  std::string name = "watch";
  uint64_t minimum = 1;
  bool missing = false;
} wallet_fixture;
std::string WalletCoin(unsigned index, const std::string& amount = "0.00000001",
                       uint64_t confirmations = 2) {
  auto coin = ScanCoin(index, amount);
  coin.pop_back();
  return coin + ",\"confirmations\":" + std::to_string(confirmations) +
      ",\"address\":\"" + kDiscoveryAddress + "\",\"spendable\":false,\"safe\":true}";
}
std::string WalletResult(const std::vector<std::string>& coins) {
  std::string result = "[";
  for (size_t i = 0; i < coins.size(); ++i) result += (i ? "," : "") + coins[i];
  return result + "]";
}
bool WalletHttp(const BitcoinCoreRpcConfig& config, const std::string& text, bool scan,
                HttpResponse* response, BitcoinRpcError* error, const std::optional<std::string>& wallet) {
  const auto request = nlohmann::json::parse(text);
  if (request["method"] != "listunspent") {
    Require(!wallet, "wallet discovery routed node calls through wallet");
    return DiscoveryHttp(config, text, scan, response, error, std::nullopt);
  }
  Require(!scan && wallet == wallet_fixture.name, "wallet route or deadline lost");
  Require(request["params"] == nlohmann::json::array({wallet_fixture.minimum, 9999999,
      nlohmann::json::array({kDiscoveryAddress}), false}), "listunspent exact bounded filter/unsafe arguments");
  discovery_fixture.requests.push_back(request);
  response->status = 200;
  response->body = "{\"jsonrpc\":\"2.0\",\"id\":" + request["id"].dump() +
      (wallet_fixture.missing ? ",\"error\":{\"code\":-18,\"message\":\"server-secret\"}}" :
       ",\"result\":" + wallet_fixture.result + "}");
  return true;
}
void TestWalletDiscovery() {
  size_t cases = 0;
  BitcoinUtxoQuery query{kDiscoveryAddress};
  auto reset = [&] {
    discovery_fixture = {};
    wallet_fixture = {};
    wallet_fixture.result = WalletResult({WalletCoin(1)});
    query = BitcoinUtxoQuery{kDiscoveryAddress}; query.wallet = wallet_fixture.name;
  };
  auto run = [&](BitcoinRpcErrorCode expected, size_t calls) {
    RpcClient client(Config(), WalletHttp);
    BitcoinUtxoDiscovery found; found.incompatibility = "sentinel";
    BitcoinRpcError error;
    const bool ok = DiscoverAddress(client, query, &found, &error);
    Require(ok == (expected == BitcoinRpcErrorCode::kNone) && error.code == expected, "wallet discovery result");
    Require(discovery_fixture.requests.size() == calls, "wallet unexpected call count or fallback");
    if (!ok) Require(found.incompatibility == "sentinel", "wallet failure changed output");
    if (wallet_fixture.missing) Require(error.rpc_code == -18, "missing wallet RPC code lost");
    Require(error.message.find("server-secret") == std::string::npos, "wallet leaked server message");
    ++cases;
    return found;
  };
  for (auto name : {std::string(), std::string(1025, 'a'), std::string("a\nb"),
                    std::string("a\0b", 3), std::string(1, static_cast<char>(0xff))}) {
    reset(); query.wallet = name; run(BitcoinRpcErrorCode::kConfiguration, 0);
  }
  reset(); query.min_confirmations = 10000000; run(BitcoinRpcErrorCode::kConfiguration, 0);
  reset(); wallet_fixture.missing = true; run(BitcoinRpcErrorCode::kRpc, 3);
  reset(); wallet_fixture.result = "null"; run(BitcoinRpcErrorCode::kMalformed, 3);
  reset(); wallet_fixture.result = "[]";
  auto found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(found.outputs.empty() && !found.challenge_compatible && !found.scan_block && !found.scan_height,
          "empty wallet result flags");
  for (const auto& name : {".", "..", "a/b?c#d%@host:123", "watch wallet", "é/財布"}) {
    reset(); query.wallet = wallet_fixture.name = name; found = run(BitcoinRpcErrorCode::kNone, 6);
    Require(found.current_rechecked && found.challenge_compatible && found.outputs.size() == 1 &&
            !found.scan_block && !found.scan_height && found.observed_height == 101,
            "watch-only wallet result/observation");
  }
  for (const auto& field : {"txid", "vout", "scriptPubKey", "confirmations"}) {
    reset(); auto coin = nlohmann::json::parse(WalletCoin(1, "1")); coin.erase(field);
    wallet_fixture.result = WalletResult({coin.dump()}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (auto patch : {nlohmann::json{{"confirmations", -1}}, nlohmann::json{{"confirmations", "2"}},
                     nlohmann::json{{"address", "another-address"}}, nlohmann::json{{"address", 1}},
                     nlohmann::json{{"vout", 4294967296ULL}},
                     nlohmann::json{{"scriptPubKey", "0014" + std::string(40, 'b')}}}) {
    reset(); auto coin = nlohmann::json::parse(WalletCoin(1, "1")); coin.update(patch);
    wallet_fixture.result = WalletResult({coin.dump()}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  for (auto amount : {"0", "-1", "1e-8", "0.000000001", "21000000.00000001", "\"0.1\""}) {
    reset(); wallet_fixture.result = WalletResult({WalletCoin(1, amount)}); run(BitcoinRpcErrorCode::kMalformed, 3);
  }
  reset(); wallet_fixture.result = WalletResult({WalletCoin(1), WalletCoin(1)}); run(BitcoinRpcErrorCode::kMalformed, 3);
  reset(); query.min_confirmations = wallet_fixture.minimum = 3;
  wallet_fixture.result = WalletResult({WalletCoin(1), WalletCoin(2, "0.00000001", 0)});
  found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(found.excluded_below_min_confirmations == 2 && found.outputs.empty(), "wallet minconf policy");
  reset(); discovery_fixture.txout = "null"; run(BitcoinRpcErrorCode::kInconclusive, 5);
  reset(); discovery_fixture.txout = LookupTxOut("0.1"); run(BitcoinRpcErrorCode::kInconclusive, 6);
  reset(); wallet_fixture.result = WalletResult({WalletCoin(2), WalletCoin(1)}); discovery_fixture.split_tip = true;
  run(BitcoinRpcErrorCode::kInconclusive, 9);
  reset(); auto unsafe = WalletCoin(1); unsafe.replace(unsafe.find("\"safe\":true"), 11, "\"safe\":false");
  wallet_fixture.result = WalletResult({unsafe}); discovery_fixture.txout = "null";
  run(BitcoinRpcErrorCode::kInconclusive, 5); // Neither safe nor spendable substitutes for chain evidence.
  reset(); wallet_fixture.result = WalletResult({WalletCoin(2), WalletCoin(1)});
  const auto wallet_outputs = run(BitcoinRpcErrorCode::kNone, 9).outputs;
  discovery_fixture = {}; discovery_fixture.scan = ScanResult({ScanCoin(1), ScanCoin(2)});
  RpcClient scan_client(Config(), DiscoveryHttp);
  BitcoinUtxoDiscovery scanned;
  Require(DiscoverAddress(scan_client, BitcoinUtxoQuery{kDiscoveryAddress}, &scanned, nullptr), "scan/wallet parity scan");
  for (size_t i = 0; i < wallet_outputs.size(); ++i)
    Require(wallet_outputs[i].claim.txid == scanned.outputs[i].claim.txid &&
            wallet_outputs[i].claim.vout == scanned.outputs[i].claim.vout &&
            wallet_outputs[i].claim.amount_sats == scanned.outputs[i].claim.amount_sats &&
            wallet_outputs[i].claim.program == scanned.outputs[i].claim.program &&
            wallet_outputs[i].confirmations == scanned.outputs[i].confirmations, "scan/wallet claim parity");
  for (unsigned count : {16, 17}) {
    reset(); std::vector<std::string> coins;
    for (unsigned i = count; i > 0; --i) coins.push_back(WalletCoin(i));
    wallet_fixture.result = WalletResult(coins);
    found = run(BitcoinRpcErrorCode::kNone, count == 16 ? 51 : 3);
    Require(found.outputs.size() == count && found.challenge_compatible == (count == 16) &&
            found.current_rechecked == (count == 16), "wallet outputs silently truncated");
  }
  for (auto amount : {"0.1", "20999999.99999999", "21000000"}) {
    reset(); wallet_fixture.result = WalletResult({WalletCoin(1, amount)});
    discovery_fixture.txout = LookupTxOut(amount);
    found = run(BitcoinRpcErrorCode::kNone, 6);
    uint64_t sats = 0;
    Require(quietproof_internal::BitcoinAmountToSats(amount, &sats) && found.outputs[0].claim.amount_sats == sats,
            "wallet original decimal changed");
  }
  reset(); wallet_fixture.result = WalletResult({WalletCoin(1, "21000000"), WalletCoin(2)});
  found = run(BitcoinRpcErrorCode::kNone, 3);
  Require(!found.challenge_compatible && found.outputs.size() == 2 && !found.current_rechecked, "wallet sum bound");
  std::cout << "Wallet discovery cases passed: " << cases << '\n';
}


// The same typed relation must survive both discovery sources and fresh evidence.
void TestTypedDiscovery() {
  const std::string p2pkh = "76a914" + std::string(40, 'a') + "88ac";
  size_t cases = 0;
  for (bool wallet : {false, true}) {
    auto run = [&](const std::string& candidate_script, const std::string& current_script,
                   BitcoinRpcErrorCode expected, unsigned count = 2,
                   const std::string& amount = "0.00000001", uint64_t minimum = 1) {
      discovery_fixture = {};
      wallet_fixture = {};
      discovery_fixture.validation = nlohmann::json{{"isvalid", true},
          {"address", kDiscoveryAddress}, {"scriptPubKey", p2pkh}}.dump();
      discovery_fixture.txout = LookupTxOut(amount, "2", current_script);
      std::vector<std::string> coins;
      for (unsigned i = count; i > 0; --i) {
        auto coin = wallet ? WalletCoin(i, amount) : ScanCoin(i, amount);
        coin.replace(coin.find(kDiscoveryScript), kDiscoveryScript.size(),
                     i == 1 ? candidate_script : p2pkh);
        coins.push_back(coin);
      }
      discovery_fixture.scan = ScanResult(coins);
      wallet_fixture.result = WalletResult(coins);
      wallet_fixture.minimum = minimum;
      BitcoinUtxoQuery query{kDiscoveryAddress};
      query.min_confirmations = minimum;
      if (wallet) query.wallet = wallet_fixture.name;
      RpcClient client(Config(), wallet ? WalletHttp : DiscoveryHttp);
      BitcoinUtxoDiscovery found; found.incompatibility = "sentinel";
      BitcoinRpcError error;
      const bool ok = DiscoverAddress(client, query, &found, &error);
      Require(ok == (expected == BitcoinRpcErrorCode::kNone) && error.code == expected,
              "typed discovery result category");
      if (!ok) Require(found.incompatibility == "sentinel", "typed failure changed output");
      ++cases;
      return found;
    };
    auto found = run(p2pkh, p2pkh, BitcoinRpcErrorCode::kNone);
    Require(found.outputs.size() == 2 && found.challenge_compatible && found.current_rechecked &&
            found.outputs[0].claim < found.outputs[1].claim, "typed discovery ordering/recheck");
    std::vector<QuietProofClaimV1> claims;
    for (const auto& coin : found.outputs) {
      Require(coin.claim.script_kind == QuietProofScriptKind::kP2pkh &&
              coin.claim.program == found.outputs.front().claim.program &&
              std::all_of(coin.claim.program.begin(), coin.claim.program.end(),
                          [](uint8_t byte) { return byte == 0xaa; }), "typed hash extraction");
      claims.push_back(coin.claim);
    }
    QuietProofStatementV1 statement;
    QuietProofChallengeOptions options{QuietProofNetwork::kRegtest, "verifier", "proof-of-funds", "message"};
    std::vector<std::array<uint8_t, 20>> keys;
    Require(CreateQuietProofChallenge(claims, options, &statement) && statement.statement_version == 2 &&
            QuietProofDistinctPrograms(statement, &keys) && keys.size() == 1,
            "typed discovery challenge/grouping");
    for (const auto& invalid : {kDiscoveryScript, p2pkh + "00", p2pkh.substr(0, 48),
         "76a94c14" + std::string(40, 'a') + "88ac", "76a914" + std::string(40, 'b') + "88ac",
         "a914" + std::string(40, 'a') + "87", std::string("zz")})
      run(invalid, p2pkh, BitcoinRpcErrorCode::kMalformed);
    for (const auto& stale : {kDiscoveryScript, p2pkh + "00", "76a914" + std::string(40, 'b') + "88ac"})
      run(p2pkh, stale, BitcoinRpcErrorCode::kInconclusive);
    found = run(p2pkh, p2pkh, BitcoinRpcErrorCode::kNone, 0);
    Require(found.outputs.empty() && !found.challenge_compatible && !found.current_rechecked,
            "typed empty discovery");
    found = run(p2pkh, p2pkh, BitcoinRpcErrorCode::kNone, 2, "0.00000001", 3);
    Require(found.outputs.empty() && found.excluded_below_min_confirmations == 2,
            "typed confirmation policy");
    found = run(p2pkh, p2pkh, BitcoinRpcErrorCode::kNone, 2, "21000000");
    Require(found.outputs.size() == 2 && !found.challenge_compatible && !found.current_rechecked,
            "typed aggregate money bound");
    run(p2pkh, p2pkh, BitcoinRpcErrorCode::kMalformed, 1, "21000000.00000001");
    // Network rejection precedes address decoding or UTXO access for either source.
    discovery_fixture = {}; discovery_fixture.chain = "main";
    RpcClient client(Config(), wallet ? WalletHttp : DiscoveryHttp);
    BitcoinUtxoQuery query{kDiscoveryAddress};
    if (wallet) query.wallet = wallet_fixture.name;
    BitcoinUtxoDiscovery output; BitcoinRpcError error;
    Require(!DiscoverAddress(client, query, &output, &error) &&
            error.code == BitcoinRpcErrorCode::kWrongNetwork && discovery_fixture.requests.size() == 1,
            "typed wrong network");
    ++cases;
  }
  std::cout << "Typed discovery cases passed: " << cases << '\n';
}

void TestLookup() {
  using Status = QuietProofChainStatus;
  QuietProofChainRequest request{QuietProofNetwork::kRegtest};
  for (size_t i = 0; i < request.txid.size(); ++i) request.txid[i] = static_cast<uint8_t>(i);
  request.vout = std::numeric_limits<uint32_t>::max();
  const std::string txid = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  size_t cases = 0;
  auto run = [&](Status expected, size_t calls, QuietProofNetwork configured = QuietProofNetwork::kRegtest) {
    auto config = Config();
    config.network = configured;
    RpcClient client(config, LookupHttp);
    const auto evidence = LookupCurrentTip(client, request);
    Require(evidence.status == expected && evidence.status != Status::kSpent, "lookup status");
    Require(lookup_fixture.requests.size() == calls, "lookup RPC count");
    for (size_t i = 0; i < calls; ++i) {
      const auto& rpc = lookup_fixture.requests[i];
      const auto params = i == 1 ? nlohmann::json::array({txid, request.vout, true}) : nlohmann::json::array();
      Require(rpc == nlohmann::json{{"jsonrpc", "2.0"}, {"id", std::to_string(i + 1)},
              {"method", i == 1 ? "gettxout" : "getblockchaininfo"}, {"params", params}},
              "lookup RPC order/params/display txid");
    }
    Require(evidence.detail.find("server-secret") == std::string::npos, "lookup leaked server text");
    ++cases;
    return evidence;
  };
  auto reset = [&] {
    lookup_fixture = {};
    lookup_fixture.results = {LookupTip(), LookupTxOut(), LookupTip()};
  };
  for (unsigned i = 0; i < 5; ++i) {
    reset();
    request.network = static_cast<QuietProofNetwork>(i);
    const auto chain = QuietProofBitcoinCoreChainName(request.network);
    lookup_fixture.results[0] = lookup_fixture.results[2] = LookupTip(chain);
    const auto evidence = run(Status::kUnspent, 3, request.network);
    Require(evidence.network == request.network && evidence.height == 100 &&
            evidence.confirmations == 2 && evidence.amount_sats == 1 &&
            evidence.script_pub_key == std::vector<uint8_t>({0, 20, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170}), "lookup evidence fields");
    for (size_t j = 0; j < 32; ++j)
      Require(evidence.block[j] == static_cast<uint8_t>((j % 8) * 34 + 1), "block bytes reversed");
  }
  request.network = QuietProofNetwork::kRegtest;
  reset(); request.has_snapshot = true; run(Status::kInconclusive, 0); request.has_snapshot = false;
  reset(); run(Status::kInconclusive, 0, QuietProofNetwork::kMainnet);
  reset(); request.network = static_cast<QuietProofNetwork>(255);
  run(Status::kInconclusive, 0, request.network); request.network = QuietProofNetwork::kRegtest;
  for (const auto& chain : {"main", "test", "signet", "testnet4", "unknown", "testnet"}) {
    reset(); lookup_fixture.results[0] = LookupTip(chain); run(Status::kWrongNetwork, 1);
  }
  reset(); lookup_fixture.results[1] = "null"; run(Status::kInconclusive, 2);
  for (const auto& tip : {LookupTip("regtest", std::string(64, 'b')),
                         LookupTip("regtest", kLookupBlock, 101), LookupTip("main")}) {
    reset(); lookup_fixture.results[2] = tip; run(Status::kInconclusive, 3);
  }
  for (const auto& hash : {std::string(63, 'a'), std::string(64, 'A'), std::string(64, 'g')}) {
    for (size_t at : {size_t{0}, size_t{2}}) {
      reset(); lookup_fixture.results[at] = LookupTip("regtest", hash); run(Status::kMalformed, at + 1);
    }
  }
  for (const auto& bad_tip : std::vector<std::string>{"null", "[]", "{}", "{\"chain\":7}",
       "{\"chain\":\"regtest\",\"bestblockhash\":\"" + kLookupBlock + "\",\"blocks\":-1}"}) {
    reset(); lookup_fixture.results[0] = bad_tip; run(Status::kMalformed, 1);
  }
  for (const auto& blocks : {"true", "1.5", "18446744073709551616", "\"100\""}) {
    for (size_t at : {size_t{0}, size_t{2}}) {
      reset();
      lookup_fixture.results[at] = "{\"chain\":\"regtest\",\"bestblockhash\":\"" +
          kLookupBlock + "\",\"blocks\":" + blocks + "}";
      run(Status::kMalformed, at + 1);
    }
  }
  // Required txout shape is checked independently from exact-money extraction.
  for (const auto& field : {"bestblock", "confirmations", "value", "scriptPubKey"}) {
    reset();
    auto malformed = nlohmann::json::parse(LookupTxOut("1"));
    malformed.erase(field);
    lookup_fixture.results[1] = malformed.dump();
    run(Status::kMalformed, 2);
  }
  for (const auto& shape : {"null", "[]", "7", "{}", "{\"hex\":7}"}) {
    reset();
    lookup_fixture.results[1] = "{\"bestblock\":\"" + kLookupBlock +
        "\",\"confirmations\":2,\"value\":1,\"scriptPubKey\":" + shape + "}";
    run(Status::kMalformed, 2);
  }
  reset();
  request.vout = 0;
  run(Status::kUnspent, 3);
  request.vout = std::numeric_limits<uint32_t>::max();
  for (const auto& amount : {"0", "-1", "21000000.00000001", "0.000000001", "1e-8", "\"0.1\"", "null", "true"}) {
    reset(); lookup_fixture.results[1] = LookupTxOut(amount); run(Status::kMalformed, 2);
  }
  for (const auto& amount : {"0.1", "20999999.99999999", "21000000", "1.23456789"}) {
    reset(); lookup_fixture.results[1] = LookupTxOut(amount);
    uint64_t expected = 0;
    Require(proofs::quietproof_internal::BitcoinAmountToSats(amount, &expected), "fixture amount");
    Require(run(Status::kUnspent, 3).amount_sats == expected, "lookup lost exact money");
  }
  for (const auto& conf : {"-1", "1.5", "1e0", "18446744073709551616", "\"2\"", "null", "true"}) {
    reset(); lookup_fixture.results[1] = LookupTxOut("0.1", conf); run(Status::kMalformed, 2);
  }
  for (const auto& conf : {"0", "18446744073709551615"}) {
    reset(); lookup_fixture.results[1] = LookupTxOut("0.1", conf); run(Status::kUnspent, 3);
  }
  for (const auto& script : {std::string(), "0014" + std::string(38, 'a'), "0014" + std::string(42, 'a'),
                            "0014" + std::string(40, 'A'), "0020" + std::string(64, 'a'),
                            "5114" + std::string(40, 'a'),
                            "76a914" + std::string(40, 'a') + "88ac00",
                            "76a94c14" + std::string(40, 'a') + "88ac",
                            "76a914" + std::string(40, 'a') + "87ac"}) {
    reset(); lookup_fixture.results[1] = LookupTxOut("0.1", "2", script); run(Status::kMalformed, 2);
  }
  reset();
  lookup_fixture.results[1] = LookupTxOut("0.1", "2", "76a914" + std::string(40, 'a') + "88ac");
  const auto typed = run(Status::kUnspent, 3);
  QuietProofClaimV1 typed_claim;
  typed_claim.amount_sats = 10000000;
  typed_claim.program.fill(0xaa);
  Require(QuietProofMatchClaim(typed_claim, request.network, typed) == Status::kInconclusive,
          "native P2PKH evidence authorized implicit P2WPKH");
  typed_claim.script_kind = QuietProofScriptKind::kP2pkh;
  Require(QuietProofMatchClaim(typed_claim, request.network, typed) == Status::kUnspent,
          "native P2PKH evidence rejected typed relation");
  reset(); lookup_fixture.results[1] = LookupTxOut("0.1", "2", "0014" + std::string(40, 'a'), std::string(64, 'b'));
  run(Status::kMalformed, 2);  // Preserve legacy mismatched-bestblock classification.
  for (const auto& bad : {"[]", "{}", "{\"value\":0.1}", "true", "{"}) {
    reset(); lookup_fixture.results[1] = bad; run(Status::kMalformed, 2);
  }
  for (size_t at = 0; at < 3; ++at) {
    for (auto code : {BitcoinRpcErrorCode::kTimeout, BitcoinRpcErrorCode::kAuthentication,
                     BitcoinRpcErrorCode::kConnection, BitcoinRpcErrorCode::kCookie}) {
      reset(); lookup_fixture.fail_at = at; lookup_fixture.failure = code; run(Status::kUnavailable, at + 1);
    }
    reset(); lookup_fixture.results[at] = "{"; run(Status::kMalformed, at + 1);
  }
  for (int status : {200, 403, 500}) {
    reset(); lookup_fixture.rpc_error = true; lookup_fixture.http_status = status; run(Status::kUnavailable, 1);
  }
  reset(); lookup_fixture.http_status = 500; run(Status::kUnavailable, 1);
  // Each Lookup performs independent RPCs, even on the same client and outpoint.
  reset(); lookup_fixture.results.insert(lookup_fixture.results.end(), {LookupTip(), "null"});
  RpcClient client(Config(), LookupHttp);
  Require(LookupCurrentTip(client, request).status == Status::kUnspent &&
          LookupCurrentTip(client, request).status == Status::kInconclusive &&
          lookup_fixture.requests.size() == 5 && lookup_fixture.requests.back()["id"] == "5", "lookup cached evidence");
  BitcoinCoreRpc native(Config());
  Require(native.kind() == QuietProofProviderKind::kCurrentTip, "native provider kind");
  request.has_snapshot = true;
  Require(native.Lookup(request).status == Status::kInconclusive, "public native snapshot rejection");
  // A caller that omits the network must never silently select mainnet or
  // issue native/legacy RPCs, even when the remaining outpoint fields are set.
  QuietProofChainRequest unspecified;
  unspecified.txid[0] = 3;
  Require(!QuietProofNetworkValid(unspecified.network), "default request selects a network");
  reset();
  RpcClient mainnet(BitcoinCoreRpcConfig{QuietProofNetwork::kMainnet}, LookupHttp);
  Require(LookupCurrentTip(mainnet, unspecified).status == Status::kInconclusive &&
          lookup_fixture.requests.empty(), "default request reached native RPC");
  size_t legacy_calls = 0;
  BitcoinCoreCurrentTipProvider legacy("/fixture/bitcoin-cli", QuietProofNetwork::kMainnet,
      [&](const std::vector<std::string>&) {
        ++legacy_calls;
        return QuietProofProcessResult{1, "", ""};
      });
  Require(legacy.Lookup(unspecified).status == Status::kInconclusive && legacy_calls == 0,
          "default request reached legacy RPC");
  ++cases;
  std::cout << "Lookup fixtures passed: " << cases + 2 << '\n';
}

// Test adapter calls the exact production operation without adding a public RPC API.
class NativeFixtureProvider final : public QuietProofChainProvider {
 public:
  explicit NativeFixtureProvider(QuietProofNetwork network) : client_(BitcoinCoreRpcConfig{network}, LookupHttp) {}
  QuietProofProviderKind kind() const override { return QuietProofProviderKind::kCurrentTip; }
  QuietProofChainEvidence Lookup(const QuietProofChainRequest& request) override {
    return LookupCurrentTip(client_, request);
  }
 private:
  RpcClient client_;
};
void SameEvidence(const QuietProofChainEvidence& a, const QuietProofChainEvidence& b) {
  Require(a.status == b.status && a.network == b.network && a.block == b.block &&
          a.height == b.height && a.confirmations == b.confirmations &&
          a.amount_sats == b.amount_sats && a.script_pub_key == b.script_pub_key,
          "legacy/native evidence differs");
  // Details are adapter-authored diagnostics, not authorization inputs.
}
QuietProofEnvelopeV1 ParityEnvelope(QuietProofNetwork network = QuietProofNetwork::kRegtest) {
  QuietProofEnvelopeV1 envelope;
  auto& statement = envelope.statement;
  statement.network = network;
  statement.verifier = "verifier";
  statement.purpose = "proof-of-funds";
  statement.not_before = 1;
  statement.expires_at = 9;
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 2;
  QuietProofClaimV1 claim;
  claim.txid[0] = 3;
  claim.amount_sats = 1;
  claim.program.fill(0xaa);
  statement.claims = {claim};
  envelope.proof.circuit_digest[0] = 1;
  envelope.proof.bytes = {1};
  return envelope;
}
std::vector<std::string> ParityResponses(const std::string& chain = "regtest") {
  return {LookupTip(chain), LookupTxOut(), LookupTip(chain)};
}
void TestProviderParity() {
  using Status = QuietProofChainStatus;
  size_t cases = 0;
  auto compare = [&](const std::vector<std::string>& results, QuietProofChainRequest request,
                     Status legacy_status, Status native_status, size_t fail_at = size_t(-1)) {
    size_t cursor = 0;
    BitcoinCoreCurrentTipProvider legacy("/fixture/bitcoin-cli", request.network,
        [&](const std::vector<std::string>& argv) {
          Require(cursor < results.size(), "legacy parity fixture exhausted");
          const auto index = cursor++;
          const auto offset = request.network == QuietProofNetwork::kMainnet ? size_t{1} : size_t{2};
          Require(argv[offset] == (index == 1 ? "gettxout" : "getblockchaininfo"), "legacy parity method order");
          if (index == fail_at) return QuietProofProcessResult{1, "", ""};
          return QuietProofProcessResult{0, results[index], ""};
        });
    const auto left = legacy.Lookup(request);
    lookup_fixture = {};
    lookup_fixture.results = results;
    lookup_fixture.fail_at = fail_at;
    NativeFixtureProvider native(request.network);
    const auto right = native.Lookup(request);
    Require(left.status == legacy_status && right.status == native_status, "parity status classification");
    Require(left.status != Status::kSpent && right.status != Status::kSpent, "RPC inferred spent evidence");
    if (legacy_status == native_status && legacy_status == Status::kUnspent) SameEvidence(left, right);
    if (left.status != Status::kUnspent)
      Require(right.status != Status::kUnspent, "legacy rejection became native evidence");
    ++cases;
  };
  for (unsigned i = 0; i < 5; ++i) {
    const auto network = static_cast<QuietProofNetwork>(i);
    QuietProofChainRequest request{network}; request.txid[0] = 3;
    const auto chain = QuietProofBitcoinCoreChainName(network);
    compare(ParityResponses(chain), request, Status::kUnspent, Status::kUnspent);
    request.has_snapshot = true;
    compare({}, request, Status::kInconclusive, Status::kInconclusive);
  }
  QuietProofChainRequest request{QuietProofNetwork::kRegtest}; request.txid[0] = 3;
  for (const auto& amount : {"0.00000001", "0.1", "12345678.12345678", "21000000"}) {
    auto results = ParityResponses(); results[1] = LookupTxOut(amount);
    compare(results, request, Status::kUnspent, Status::kUnspent);
  }
  for (const auto& txout : {std::string("null"), LookupTxOut("1e-8"), LookupTxOut("-1"),
       LookupTxOut("0.000000001"), LookupTxOut("\"0.1\""), LookupTxOut("21000000.00000001"),
       LookupTxOut("1", "-1"), LookupTxOut("1", "1.5"), LookupTxOut("1", "18446744073709551616"),
       LookupTxOut("1", "2", "0014FF"), LookupTxOut("1", "2", "0014" + std::string(40, 'a'), std::string(64, 'b')),
       std::string("{"), std::string("{}")}) {
    auto results = ParityResponses(); results[1] = txout;
    const auto expected = txout == "null" ? Status::kInconclusive : Status::kMalformed;
    compare(results, request, expected, expected);
  }
  for (const auto& tip : {LookupTip("regtest", std::string(64, 'b')),
                        LookupTip("regtest", kLookupBlock, 101), LookupTip("main")}) {
    auto results = ParityResponses(); results[2] = tip;
    compare(results, request, Status::kInconclusive, Status::kInconclusive);
  }
  auto wrong = ParityResponses("unknown");
  compare(wrong, request, Status::kWrongNetwork, Status::kWrongNetwork);
  // Intentional native hardening: malformed JSON/tip data have explicit malformed
  // diagnostics; legacy collapses the initial failure into unavailable and the
  // final one into inconclusive. Neither can authorize verification.
  for (size_t at : {size_t{0}, size_t{2}}) {
    auto results = ParityResponses(); results[at] = "{}";
    compare(results, request, at == 0 ? Status::kUnavailable : Status::kInconclusive, Status::kMalformed);
  }
  for (size_t at = 0; at < 3; ++at)
    compare(ParityResponses(), request, at == 2 ? Status::kInconclusive : Status::kUnavailable,
            Status::kUnavailable, at);
  // Zero amounts and non-P2WPKH decoded scripts are legacy evidence but cannot
  // match a valid positive P2WPKH claim. Native rejects them earlier.
  for (const auto& txout : {LookupTxOut("0"), LookupTxOut("1", "2", "0020" + std::string(64, 'a')),
                           LookupTxOut("1", "2", "0014" + std::string(42, 'a'))}) {
    auto results = ParityResponses(); results[1] = txout;
    compare(results, request, Status::kUnspent, Status::kMalformed);
  }
  // Duplicate non-money JSON keys are rejected by native SAX validation; legacy
  // DOM parsing keeps the final value. A duplicate monetary key fails both.
  auto duplicate = ParityResponses();
  duplicate[1] = LookupTxOut(); duplicate[1].insert(1, "\"confirmations\":3,");
  compare(duplicate, request, Status::kUnspent, Status::kMalformed);
  duplicate[1] = LookupTxOut(); duplicate[1].insert(1, "\"value\":1,");
  compare(duplicate, request, Status::kMalformed, Status::kMalformed);
  std::cout << "Provider parity fixtures passed: " << cases << '\n';
}
void TestVerifierParity() {
  using Result = QuietProofVerifyResult;
  size_t cases = 0;
  using Configure = std::function<void(QuietProofVerifierConfig&)>;
  auto check = [&](const QuietProofEnvelopeV1& envelope, const std::vector<std::string>& results,
                   Result expected, Configure configure = {}, bool replay = false,
                   size_t fail_at = size_t(-1), bool same_claim_evidence = true) {
    std::vector<uint8_t> wire;
    Require(EncodeQuietProofEnvelope(envelope, &wire), "encode verifier parity envelope");
    QuietProofVerification previous;
    size_t previous_calls = 0;
    for (bool use_native : {false, true}) {
      lookup_fixture = {}; lookup_fixture.results = results; lookup_fixture.fail_at = fail_at;
      size_t cursor = 0;
      BitcoinCoreCurrentTipProvider legacy("/fixture/bitcoin-cli", envelope.statement.network,
          [&](const std::vector<std::string>&) {
            Require(cursor < results.size(), "verifier parity fixture exhausted");
            const auto index = cursor++;
            return QuietProofProcessResult{index == fail_at ? 1 : 0, results[index], ""};
          });
      NativeFixtureProvider native(envelope.statement.network);
      QuietProofVerifierConfig config;
      config.provider = use_native ? static_cast<QuietProofChainProvider*>(&native) : &legacy;
      config.policy.now = 2;
      config.policy.verifier = "verifier";
      config.policy.purpose = envelope.statement.purpose;
      config.min_confirmations = 1;
      size_t nonce_attempts = 0, consumed = 0;
      bool seen = false;
      config.policy.nonce_seen = [&](const auto&) { return seen; };
      config.policy.consume_nonce = [&](const auto& nonce) {
        Require(nonce == envelope.statement.nonce, "verifier changed nonce");
        ++nonce_attempts;
        if (seen) return false;
        seen = true; ++consumed; return true;
      };
      config.verify_proof = [](const auto&) { return true; };
      if (configure) configure(config);
      const auto outcome = VerifyQuietProof(wire, config);
      const size_t calls = use_native ? lookup_fixture.requests.size() : cursor;
      Require(outcome.result == expected, "legacy/native verifier result");
      const bool success = expected == Result::kValidCurrent;
      Require(consumed == (success ? 1 : 0) && nonce_attempts == (success ? 1 : 0),
              "failed verification consumed or attempted nonce");
      if (use_native) {
        Require(outcome.result == previous.result && outcome.total_sats == previous.total_sats,
                "legacy rejection became native authorization");
        if (same_claim_evidence) {
          Require(outcome.claims.size() == previous.claims.size() && calls == previous_calls,
                  "verifier evidence/call parity");
          for (size_t i = 0; i < outcome.claims.size(); ++i) SameEvidence(outcome.claims[i], previous.claims[i]);
        }
      }
      if (replay) {
        Require(success && VerifyQuietProof(wire, config).result == Result::kInvalidProof &&
                consumed == 1 && nonce_attempts == 1 &&
                (use_native ? lookup_fixture.requests.size() : cursor) == calls,
                "replay reached RPC or consumed nonce twice");
      }
      previous = outcome; previous_calls = calls;
    }
    ++cases;
  };
  auto envelope = ParityEnvelope();
  auto responses = ParityResponses();
  for (unsigned i = 0; i < 5; ++i) {
    auto network = static_cast<QuietProofNetwork>(i);
    check(ParityEnvelope(network), ParityResponses(QuietProofBitcoinCoreChainName(network)), Result::kValidCurrent, {}, true);
  }
  check(envelope, responses, Result::kStaleSnapshot, [](auto& c) { c.min_confirmations = 3; });
  check(envelope, responses, Result::kStateInconclusive, [](auto& c) { c.minimum_total_sats = 2; });
  for (const Configure& policy : std::vector<Configure>{
       [](auto& c) { c.policy.verifier = "other"; }, [](auto& c) { c.policy.purpose = "other"; },
       [](auto& c) { c.policy.now = 9; }, [](auto& c) { c.policy.now = 0; },
       [](auto& c) { c.policy.max_lifetime = 1; },
       [](auto& c) { c.policy.nonce_seen = [](const auto&) { return true; }; },
       [](auto& c) { c.verify_proof = [](const auto&) { return false; }; }})
    check(envelope, {}, Result::kInvalidProof, policy);
  check(envelope, responses, Result::kInvalidProof, [](auto& c) { c.policy.consume_nonce = {}; });
  check(envelope, {}, Result::kUnsupported, [](auto& c) { c.supports = [](const auto&) { return false; }; });
  auto historical = envelope; historical.statement.has_snapshot = true;
  historical.statement.snapshot[0] = 1; historical.statement.snapshot_height = 100;
  check(historical, {}, Result::kStateInconclusive);
  auto bound = envelope; bound.statement.has_bridge_binding = true;
  bound.statement.purpose = "bridge-authorization";
  bound.statement.bridge.destination_commitment[0] = 1;
  bound.statement.bridge.lock_id[0] = 1;
  bound.statement.bridge.asset_id = "asset";
  check(bound, responses, Result::kBridgeRejected);
  check(bound, responses, Result::kBridgeRejected, [](auto& c) { c.bridge_authorized = [](const auto&) { return false; }; });
  check(bound, responses, Result::kValidCurrent, [](auto& c) { c.bridge_authorized = [](const auto&) { return true; }; });
  auto multiple = envelope; auto second = multiple.statement.claims[0]; second.txid[0] = 4;
  multiple.statement.claims.push_back(second);
  auto both = responses; both.insert(both.end(), responses.begin(), responses.end());
  check(multiple, both, Result::kValidCurrent, {}, true);
  for (bool change_height : {false, true}) {
    auto changed = both;
    const auto hash = change_height ? kLookupBlock : std::string(64, 'b');
    changed[3] = changed[5] = LookupTip("regtest", hash, change_height ? 101 : 100);
    changed[4] = LookupTxOut("0.00000001", "2", "0014" + std::string(40, 'a'), hash);
    check(multiple, changed, Result::kStateInconclusive);
  }
  for (const auto& txout : {std::string("null"), LookupTxOut("0.00000002"),
       LookupTxOut("0.00000001", "2", "0014" + std::string(40, 'b')),
       LookupTxOut("0.00000001", "2", "0014" + std::string(40, 'a'), std::string(64, 'b')),
       LookupTxOut("1e-8"), LookupTxOut("0.000000001"), LookupTxOut("1", "-1"),
       LookupTxOut("-1"), LookupTxOut("21000000.00000001"), LookupTxOut("\"0.1\""),
       LookupTxOut("1", "18446744073709551616"), LookupTxOut("1", "1.5"),
       LookupTxOut("1", "2", "0014FF"), std::string("{"), std::string("{}")}) {
    auto failed = responses; failed[1] = txout;
    check(envelope, failed, Result::kStateInconclusive);
  }
  auto wrong = ParityResponses("main"); check(envelope, wrong, Result::kStateInconclusive);
  auto moved = responses; moved[2] = LookupTip("regtest", kLookupBlock, 101);
  check(envelope, moved, Result::kStateInconclusive, {}, false, size_t(-1), false);
  for (size_t at = 0; at < 3; ++at)
    check(envelope, responses, Result::kStateInconclusive, {}, false, at, false);
  // Earlier native failures may contain less partial evidence, but the unchanged
  // verifier rejects both backends before attempting nonce consumption.
  for (const auto& txout : {LookupTxOut("0"), LookupTxOut("1", "2", "0020" + std::string(64, 'a'))}) {
    auto failed = responses; failed[1] = txout;
    check(envelope, failed, Result::kStateInconclusive, {}, false, size_t(-1), false);
  }
  // Atomic nonce-store rejection models another verifier winning the race
  // after nonce_seen. Authorization fails even though all chain evidence passed.
  for (bool use_native : {false, true}) {
    lookup_fixture = {}; lookup_fixture.results = responses;
    size_t cursor = 0, attempts = 0;
    BitcoinCoreCurrentTipProvider legacy("/fixture/bitcoin-cli", envelope.statement.network,
        [&](const auto&) { return QuietProofProcessResult{0, responses.at(cursor++), ""}; });
    NativeFixtureProvider native(envelope.statement.network);
    QuietProofVerifierConfig config;
    config.provider = use_native ? static_cast<QuietProofChainProvider*>(&native) : &legacy;
    config.policy.now = 2; config.policy.verifier = "verifier"; config.policy.purpose = "proof-of-funds";
    config.policy.nonce_seen = [](const auto&) { return false; };
    config.policy.consume_nonce = [&](const auto&) { ++attempts; return false; };
    config.verify_proof = [](const auto&) { return true; };
    std::vector<uint8_t> wire;
    Require(EncodeQuietProofEnvelope(envelope, &wire), "encode nonce race fixture");
    Require(VerifyQuietProof(wire, config).result == Result::kInvalidProof && attempts == 1,
            "nonce race rejection authorized");
  }
  ++cases;
  std::cout << "Verifier parity fixtures passed: " << cases << " per backend\n";
}
void TestPublicProviderHttp(const std::string& url, const std::string& cookie, const std::string& scenario) {
  auto config = Config(); config.rpc_url = url; config.rpc_cookie = cookie;
  BitcoinCoreRpc provider(config);
  auto envelope = ParityEnvelope();
  QuietProofChainRequest request{envelope.statement.network, envelope.statement.claims[0].txid};
  const auto evidence = provider.Lookup(request);
  if (scenario == "provider-ok") {
    Require(evidence.status == QuietProofChainStatus::kUnspent && evidence.amount_sats == 1 &&
            evidence.confirmations == 2 && evidence.height == 100 &&
            QuietProofMatchClaim(envelope.statement.claims[0], request.network, evidence) == QuietProofChainStatus::kUnspent,
            "public native HTTP forwarding/evidence");
  } else Require(evidence.status == QuietProofChainStatus::kInconclusive, "public native null lookup");
  QuietProofVerifierConfig verifier;
  verifier.provider = &provider;
  verifier.policy.now = 2; verifier.policy.verifier = "verifier"; verifier.policy.purpose = "proof-of-funds";
  size_t consumed = 0;
  verifier.policy.consume_nonce = [&](const auto&) { ++consumed; return true; };
  verifier.verify_proof = [](const auto&) { return true; };
  verifier.min_confirmations = 1;
  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "public provider envelope");
  const auto result = VerifyQuietProof(wire, verifier);
  Require(result.result == (scenario == "provider-ok" ? QuietProofVerifyResult::kValidCurrent :
                                                       QuietProofVerifyResult::kStateInconclusive) &&
          consumed == (scenario == "provider-ok" ? 1 : 0), "public provider verifier/nonce contract");
}
void TestHttp(const std::string& url, const std::string& cookie, const std::string& scenario) {
  auto config = Config();
  config.rpc_url = url;
  config.rpc_cookie = cookie;
  config.connect_timeout = std::chrono::milliseconds(200);
  config.rpc_timeout = std::chrono::milliseconds(scenario == "scan-timeout" ? 2000 : 150);
  config.scan_timeout = std::chrono::milliseconds(scenario == "scan-deadline" ? 1000 : 150);
  HttpResponse response{777, "unchanged"};
  BitcoinRpcError error{BitcoinRpcErrorCode::kCookie, 999, 12, "old-error"};
  const bool result = PostRpcHttp(config, R"({"jsonrpc":"2.0","id":"fixture","method":"getblockchaininfo","params":[]})",
                                  scenario.starts_with("scan-"), &response, &error);
  if (scenario == "ok" || scenario == "scan-deadline" || scenario == "exact-body" || scenario == "identity") {
    Require(result && response.status == 200 && error.code == BitcoinRpcErrorCode::kNone &&
            error.message.empty() && !error.rpc_code && error.http_status == 0, "HTTP success contract");
    if (scenario == "exact-body") Require(response.body.size() == kMaxBodyBytes, "exact streamed body size");
    else Require(response.body == "fixture-response", "HTTP body bytes changed");
    return;
  }
  Require(!result, "adversarial HTTP accepted");
  if (error.code == BitcoinRpcErrorCode::kHttp)
    Require(response.status != 777 && !response.body.empty(), "HTTP diagnostics not retained privately");
  else Require(response.status == 777 && response.body == "unchanged", "HTTP failure changed output");
  const auto expected = scenario == "auth" ? BitcoinRpcErrorCode::kAuthentication :
      scenario == "timeout" || scenario == "scan-timeout" ? BitcoinRpcErrorCode::kTimeout :
      scenario == "large-body" || scenario == "large-chunked" || scenario == "large-headers" ? BitcoinRpcErrorCode::kResponseTooLarge :
      scenario == "compression" || scenario == "folded-compression" ? BitcoinRpcErrorCode::kMalformed :
      scenario == "refused" || scenario == "truncated" ? BitcoinRpcErrorCode::kConnection : BitcoinRpcErrorCode::kHttp;
  Require(error.code == expected, "HTTP failure category");
  if (scenario == "auth") Require(error.http_status == 401, "HTTP auth status");
  if (scenario == "redirect") Require(error.http_status == 302, "HTTP redirect status");
  Require(error.message.find("server-secret") == std::string::npos &&
          error.message.find("cookie-secret") == std::string::npos && error.message.find(url) == std::string::npos,
          "HTTP diagnostic leaked untrusted data");
}
void TestClientHttp(const std::string& url, const std::string& cookie, const std::string& scenario) {
  auto config = Config();
  config.rpc_url = url;
  config.rpc_cookie = cookie;
  RpcClient client(config);
  RpcDecodedResponse response;
  response.result = "sentinel";
  BitcoinRpcError error;
  const auto params = nlohmann::json::array({"quoted\"\\\ninput"});
  const bool success = client.Call("gettxout", params, false, &response, &error);
  if (scenario == "rpc-ok" || scenario == "rpc-null" ||
      scenario == "rpc-money-scan" || scenario == "rpc-money-wallet") {
    Require(success && error.code == BitcoinRpcErrorCode::kNone, "real HTTP RPC success");
    if (scenario == "rpc-null") Require(response.result.is_null(), "real HTTP null result");
    else {
      const std::string path = scenario == "rpc-money-scan" ? "/result/unspents/0/amount" :
          scenario == "rpc-money-wallet" ? "/result/0/amount" : "/result/value";
      Require(response.money.at(path).sats == 1 && response.money.at(path).token == "0.00000001",
              "real HTTP exact amount");
    }
    if (scenario == "rpc-ok")
      Require(client.Call("gettxout", params, false, &response, &error), "second real HTTP RPC");
  } else {
    Require(!success && response.result == "sentinel", "real HTTP RPC failure changed result");
    const auto expected = scenario == "rpc-error" || scenario == "rpc-error500" ? BitcoinRpcErrorCode::kRpc :
        scenario == "rpc-success500" ? BitcoinRpcErrorCode::kHttp : BitcoinRpcErrorCode::kMalformed;
    Require(error.code == expected, "real HTTP RPC error category");
    if (expected == BitcoinRpcErrorCode::kRpc)
      Require(error.rpc_code == -8 && error.http_status == (scenario == "rpc-error500" ? 500 : 200),
              "real HTTP RPC diagnostic code/status");
    Require(error.message.find("server-secret") == std::string::npos, "real RPC error leaked");
  }
}
void TestPublicDiscoveryHttp(const std::string& url, const std::string& cookie,
                             const std::string& scenario) {
  auto config = Config();
  config.rpc_url = url;
  config.rpc_cookie = cookie;
  config.scan_timeout = std::chrono::milliseconds(100);
  BitcoinCoreRpc client(config);
  BitcoinUtxoDiscovery found;
  found.incompatibility = "sentinel";
  BitcoinRpcError error;
  const bool ok = client.Discover(BitcoinUtxoQuery{kDiscoveryAddress}, &found, &error);
  if (scenario == "discovery-ok" || scenario == "discovery-p2pkh" || scenario == "discovery-empty") {
    Require(ok && error.code == BitcoinRpcErrorCode::kNone, "public discovery failed");
    Require(found.outputs.size() == (scenario != "discovery-empty" ? 1 : 0), "public discovery outputs");
    Require(found.scan_height == 100 && found.current_rechecked == (scenario != "discovery-empty"),
            "public discovery observation");
    if (scenario != "discovery-empty")
      Require(found.outputs[0].claim.amount_sats == 1 && found.observed_height == 101 &&
              found.outputs[0].confirmations == 3, "public exact money/tip advance");
    if (scenario == "discovery-p2pkh")
      Require(found.outputs[0].claim.script_kind == QuietProofScriptKind::kP2pkh, "HTTP typed scan lost kind");
  } else {
    const auto expected = scenario == "discovery-invalid" ? BitcoinRpcErrorCode::kInvalidAddress :
        scenario == "discovery-unsupported" ? BitcoinRpcErrorCode::kUnsupportedScript :
        scenario == "discovery-busy" ? BitcoinRpcErrorCode::kScanBusy :
        scenario == "discovery-timeout" ? BitcoinRpcErrorCode::kTimeout : BitcoinRpcErrorCode::kScanIncomplete;
    Require(!ok && error.code == expected && found.incompatibility == "sentinel", "public discovery error");
  }
}
void TestPublicWalletHttp(const std::string& url, const std::string& cookie,
                          const std::string& scenario) {
  auto config = Config(); config.rpc_url = url; config.rpc_cookie = cookie;
  BitcoinCoreRpc client(config);
  BitcoinUtxoQuery query{kDiscoveryAddress};
  query.wallet = scenario == "wallet-dot" ? "." : scenario == "wallet-dotdot" ? ".." :
      scenario == "wallet-unicode" ? "é/財布" : "watch /../?x#%@:123";
  BitcoinUtxoDiscovery found; found.incompatibility = "sentinel";
  BitcoinRpcError error;
  const bool ok = client.Discover(query, &found, &error);
  if (scenario == "wallet-missing" || scenario == "wallet-redirect" || scenario == "wallet-auth") {
    const auto expected = scenario == "wallet-missing" ? BitcoinRpcErrorCode::kRpc :
        scenario == "wallet-auth" ? BitcoinRpcErrorCode::kAuthentication : BitcoinRpcErrorCode::kHttp;
    Require(!ok && error.code == expected && found.incompatibility == "sentinel", "public wallet failure");
    if (scenario == "wallet-missing") Require(error.rpc_code == -18 && error.http_status == 500, "missing wallet diagnostics");
  } else {
    Require(ok && error.code == BitcoinRpcErrorCode::kNone && found.outputs.size() == 1 &&
            found.outputs[0].claim.amount_sats == 1 && found.current_rechecked && found.challenge_compatible &&
            !found.scan_block && !found.scan_height && found.observed_height == 101,
            "public wallet route/recheck result");
    if (scenario == "wallet-p2pkh")
      Require(found.outputs[0].claim.script_kind == QuietProofScriptKind::kP2pkh, "HTTP typed wallet lost kind");
  }
}
void TestRotation(const std::string& url, const std::string& cookie) {
  TestHttp(url, cookie, "ok");
  WriteCookie(cookie, "__cookie__:rotated-secret");
  TestHttp(url, cookie, "ok");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc == 5 && std::string(argv[1]) == "--wallet") TestPublicWalletHttp(argv[2], argv[3], argv[4]);
    else if (argc == 5 && std::string(argv[1]) == "--discover") TestPublicDiscoveryHttp(argv[2], argv[3], argv[4]);
    else if (argc == 5 && std::string(argv[1]) == "--provider") TestPublicProviderHttp(argv[2], argv[3], argv[4]);
    else if (argc == 5 && std::string(argv[1]) == "--http") TestHttp(argv[2], argv[3], argv[4]);
    else if (argc == 5 && std::string(argv[1]) == "--rpc") TestClientHttp(argv[2], argv[3], argv[4]);
    else if (argc == 4 && std::string(argv[1]) == "--rotate") TestRotation(argv[2], argv[3]);
    else if (argc == 1) { TestConfig(); TestCallbacks(); TestCookies(); TestEnvelopes(); TestExactMoney(); TestRequests(); TestLookup(); TestProviderParity(); TestVerifierParity(); TestDiscovery(); TestWalletDiscovery(); TestTypedDiscovery(); }
    else throw std::runtime_error("invalid test arguments");
    std::cout << "RPC adapter checks passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "RPC adapter test failed: " << error.what() << '\n';
    return 1;
  }
}
