#include "node_settings.h"
#include "preferences.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace quietproof::gui {
namespace {
bool BoundedText(std::string_view text, size_t limit) {
  return text.size() <= limit && std::none_of(text.begin(), text.end(), [](unsigned char c) {
    return c < 32 || c == 127;
  });
}
bool Number(const char* text, int maximum, int* output) {
  const std::string_view value(text);
  const auto [end, error] = std::from_chars(value.data(), value.data()+value.size(), *output);
  return error == std::errc{} && end == value.data()+value.size() && *output > 0 && *output <= maximum;
}
}
void NodeSettings::Set(NodeField field, const std::string& text) {
  auto& buffer = fields[static_cast<size_t>(field)];
  buffer.fill(0);
  std::memcpy(buffer.data(), text.data(), std::min(text.size(),buffer.size()-1));
}
const char* NodeFieldLabel(NodeField field) {
  constexpr const char* labels[] = {"Host (blank: 127.0.0.1)", "Port (blank: network default)",
    "Data directory (blank: Bitcoin default)", "Cookie path (overrides data directory)",
    "Wallet (blank: select after test)", "Connect timeout ms (blank: 5000)",
    "RPC timeout ms (blank: 30000)"};
  return labels[static_cast<size_t>(field)];
}
std::optional<NodeConfiguration> ConfigureNode(const NodeSettings& settings,
    proofs::QuietProofNetwork network, std::string* error) {
  auto fail = [&](const char* message) -> std::optional<NodeConfiguration> {
    if (error) *error = message;
    return std::nullopt;
  };
  for (size_t i=0; i<settings.fields.size(); ++i) {
    const auto& buffer = settings.fields[i];
    const auto end = std::find(buffer.begin(),buffer.end(),0);
    if (end == buffer.end() || !BoundedText(std::string_view(buffer.data(),end-buffer.begin()),
        i == static_cast<size_t>(NodeField::Wallet) ? 1024 : 4095))
      return fail("Connection fields are too long or contain control characters.");
  }
  NodeConfiguration result{proofs::BitcoinCoreRpcConfig(network), {}, settings.Text(NodeField::Wallet)};
  result.rpc.rpc_datadir = settings.Text(NodeField::DataDirectory);
  result.rpc.rpc_cookie = settings.Text(NodeField::CookiePath);
  // Resolve network defaults using the same code that transport uses.
  proofs::BitcoinRpcError rpc_error;
  if (!proofs::ResolveBitcoinRpcSettings(result.rpc,&result.resolved,&rpc_error))
    return fail(rpc_error.message.c_str());
  std::string host = settings.Text(NodeField::Host);
  if (host.empty() || host == "localhost") host = "127.0.0.1";
  // Host is a literal, never URL syntax. IPv6 loopback may be entered unbracketed.
  if (host == "::1") host = "[::1]";
  if (host != "[::1]" && host.find_first_of(":/@?#\\[]") != std::string::npos)
    return fail("Host must be localhost or a numeric loopback address, without a URL or credentials.");
  std::string port = settings.Text(NodeField::Port);
  int number = 0;
  if (!port.empty() && !Number(port.c_str(),65535,&number)) return fail("Port must be 1 to 65535, or blank.");
  if (port.empty()) {
    const auto start = result.resolved.url.rfind(':')+1;
    port = result.resolved.url.substr(start,result.resolved.url.find('/',start)-start);
  }
  result.rpc.rpc_url = "http://"+host+":"+port+"/";
  for (const auto field : {NodeField::ConnectTimeout,NodeField::RpcTimeout}) {
    if (!*settings.Text(field)) continue;
    if (!Number(settings.Text(field),60000,&number)) return fail("GUI timeouts must be 1 to 60000 ms, or blank.");
    (field == NodeField::ConnectTimeout ? result.rpc.connect_timeout : result.rpc.rpc_timeout) =
        std::chrono::milliseconds(number);
  }
  if (!proofs::ResolveBitcoinRpcSettings(result.rpc,&result.resolved,&rpc_error))
    return fail(rpc_error.message.c_str());
  if (error) error->clear();
  return result;
}
NodeSettings LoadNodeSettings(const std::filesystem::path& path, std::string* status) {
  if (status) status->clear();
  std::error_code error;
  if (!std::filesystem::exists(path,error) && !error) return {};
  auto invalid = [&] {
    if (status) *status = "Connection settings could not be read; defaults restored.";
    return NodeSettings{};
  };
  const auto size = std::filesystem::file_size(path,error);
  if (error || size > 32768) return invalid();
  std::ifstream input(path);
  std::string line;
  if (!std::getline(input,line) || line != "quietproof-node=1") return invalid();
  NodeSettings settings;
  for (size_t i=0; i<settings.fields.size(); ++i) {
    if (!std::getline(input,line)) return invalid();
    std::istringstream row(line);
    size_t index = 99;
    std::string text;
    if (!(row >> index >> std::quoted(text)) || index != i || !(row >> std::ws).eof() ||
        !BoundedText(text,i == static_cast<size_t>(NodeField::Wallet) ? 1024 : 4095)) return invalid();
    settings.Set(static_cast<NodeField>(i),text);
  }
  if (std::getline(input,line)) return invalid();
  if (!ConfigureNode(settings,proofs::QuietProofNetwork::kMainnet,nullptr)) return invalid();
  return settings;
}
bool SaveNodeSettings(const std::filesystem::path& path, const NodeSettings& settings) {
  if (!ConfigureNode(settings,proofs::QuietProofNetwork::kMainnet,nullptr)) return false;
  std::ostringstream output;
  output << "quietproof-node=1\n";
  for (size_t i=0; i<settings.fields.size(); ++i)
    output << i << ' ' << std::quoted(settings.fields[i].data()) << '\n';
  return SavePrivatePreferences(path,output.str());
}
}  // namespace quietproof::gui
