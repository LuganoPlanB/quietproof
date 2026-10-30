#pragma once

#include "quietproof/bitcoin_rpc.h"

#include <array>
#include <filesystem>
#include <optional>
#include <string>

namespace quietproof::gui {
// Text buffers are bounded and contain only nonsecret connection choices.
// Empty fields inherit transport defaults; explicit overrides survive network changes.
enum class NodeField { Host, Port, DataDirectory, CookiePath, Wallet, ConnectTimeout, RpcTimeout, Count };
struct NodeSettings {
  using Buffer = std::array<char, 4096>;
  std::array<Buffer, static_cast<size_t>(NodeField::Count)> fields{};
  char* Text(NodeField field) { return fields[static_cast<size_t>(field)].data(); }
  const char* Text(NodeField field) const { return fields[static_cast<size_t>(field)].data(); }
  void Set(NodeField field, const std::string& text);
};
struct NodeConfiguration {
  proofs::BitcoinCoreRpcConfig rpc;
  proofs::BitcoinRpcSettings resolved;
  std::string wallet;
};
std::optional<NodeConfiguration> ConfigureNode(const NodeSettings&, proofs::QuietProofNetwork,
                                              std::string* error);
NodeSettings LoadNodeSettings(const std::filesystem::path&, std::string* status);
bool SaveNodeSettings(const std::filesystem::path&, const NodeSettings&);
const char* NodeFieldLabel(NodeField);
}  // namespace quietproof::gui
