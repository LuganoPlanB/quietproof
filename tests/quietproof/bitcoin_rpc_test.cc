// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include "bitcoin_rpc_internal.h"
#include "bitcoin_rpc_json.h"

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
              HttpResponse* response, BitcoinRpcError* error) {
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
void TestRotation(const std::string& url, const std::string& cookie) {
  TestHttp(url, cookie, "ok");
  WriteCookie(cookie, "__cookie__:rotated-secret");
  TestHttp(url, cookie, "ok");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc == 5 && std::string(argv[1]) == "--http") TestHttp(argv[2], argv[3], argv[4]);
    else if (argc == 5 && std::string(argv[1]) == "--rpc") TestClientHttp(argv[2], argv[3], argv[4]);
    else if (argc == 4 && std::string(argv[1]) == "--rotate") TestRotation(argv[2], argv[3]);
    else if (argc == 1) { TestConfig(); TestCallbacks(); TestCookies(); TestEnvelopes(); TestExactMoney(); TestRequests(); }
    else throw std::runtime_error("invalid test arguments");
    std::cout << "RPC adapter checks passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "RPC adapter test failed: " << error.what() << '\n';
    return 1;
  }
}
