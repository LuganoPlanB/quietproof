// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only file interface. Never prints a receipt, key, signature or RPC body.
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include "cli/json.hpp"
#include "quietproof/bitcoin_rpc.h"

int main(int argc, char** argv) {
  using namespace proofs;
  try {
    if (argc != 2) throw 1;
    std::ifstream stream(argv[1], std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(stream)), {});
    if (!stream || text.size() > 32768) throw 1;
    const auto input = nlohmann::json::parse(text);
    const auto encoded = input.at("request").get<std::string>();
    if (encoded.size() % 2 || encoded.size() > 8194) throw 1;
    std::vector<uint8_t> request;
    const auto nibble = [](char c) { return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1; };
    for (size_t i = 0; i < encoded.size(); i += 2) {
      if (nibble(encoded[i]) < 0 || nibble(encoded[i+1]) < 0) throw 1;
      request.push_back(static_cast<uint8_t>(16*nibble(encoded[i])+nibble(encoded[i+1])));
    }
    BitcoinCoreRpcConfig config{QuietProofNetwork::kRegtest};
    config.rpc_url = input.at("url").get<std::string>();
    config.rpc_cookie = input.at("cookie").get<std::string>();
    config.rpc_timeout = std::chrono::milliseconds(input.value("timeout_ms", 3000));
    BitcoinCoreRpc rpc(config);
    std::vector<uint8_t> receipt{0xaa,0xbb};
    BitcoinRpcError error;
    int callbacks = 0;
    const auto stop = [&] { return ++callbacks == input.value("stop_at", 0); };
    const bool success = rpc.AuthorizeSignature(input.at("wallet").get<std::string>(), request,
        input.value("null_output", false) ? nullptr : &receipt, &error, stop);
    if (!success && receipt != std::vector<uint8_t>{0xaa,0xbb}) throw 1;
    if (success) {
      const auto path = input.at("output").get<std::string>();
      const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) throw 1;
      const auto count = write(fd, receipt.data(), receipt.size());
      const int closed = close(fd);
      if (count != static_cast<ssize_t>(receipt.size()) || closed != 0) { unlink(path.c_str()); throw 1; }
    }
    std::cout << (success ? "ok" : "rejected") << ' ' << static_cast<int>(error.code) << '\n';
    if (!success) std::cerr << error.message << '\n';
    return success ? 0 : 2;
  } catch (...) { std::cerr << "signature adapter driver failed\n"; return 1; }
}
