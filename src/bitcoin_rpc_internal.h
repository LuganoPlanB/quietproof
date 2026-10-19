// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SRC_BITCOIN_RPC_INTERNAL_H_
#define QUIETPROOF_SRC_BITCOIN_RPC_INTERNAL_H_

#include <cstddef>
#include <string>
#include <sys/types.h>

#include "quietproof/bitcoin_rpc.h"

namespace proofs::bitcoin_rpc_internal {
inline constexpr std::size_t kMaxBodyBytes = std::size_t{1024} * 1024;
inline constexpr std::size_t kMaxHeaderBytes = std::size_t{32} * 1024;
inline constexpr std::size_t kMaxCookieBytes = 4096;
struct ResolvedRpcConfig {
  std::string url;
  std::string cookie_path;
};
struct HttpResponse {
  int status = 0;
  std::string body;
};
// Private seam for bounded adapter tests. No JSON decoding or arbitrary public RPC.
bool ResolveRpcConfig(const BitcoinCoreRpcConfig&, ResolvedRpcConfig*,
                      BitcoinRpcError*);
// kHttp failures retain the bounded response here for private RPC diagnostics.
// All other failures leave output unchanged. Public results remain unchanged.
bool PostRpcHttp(const BitcoinCoreRpcConfig&, const std::string& request,
                 bool scan, HttpResponse*, BitcoinRpcError*,
                 const std::optional<std::string>& wallet = std::nullopt);
bool SecureCookieMetadata(mode_t mode, uid_t owner, uid_t effective_user);

struct HttpBuffers {
  std::string body;
  std::size_t header_bytes = 0;
  bool too_large = false;
  bool unsupported_encoding = false;
  bool buffer_failure = false;
};
std::size_t HttpBodyCallback(char*, std::size_t, std::size_t, void*) noexcept;
std::size_t HttpHeaderCallback(char*, std::size_t, std::size_t, void*) noexcept;
}  // namespace proofs::bitcoin_rpc_internal
#endif
