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

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "proof_progress.h"
#include "quietproof/bitcoin_core.h"
#ifdef QUIETPROOF_HAS_RPC
#include "quietproof/bitcoin_rpc.h"
#endif
#include "quietproof/challenge.h"
#include "quietproof/envelope.h"
#include "quietproof/nonce_store.h"
#include "pokc/prover.h"
#include "quietproof/verifier.h"
#include "cli/json.hpp"

namespace {

constexpr int kUsage = 64;
constexpr int kData = 65;
constexpr int kSoftware = 70;
constexpr int kIoError = 74;
constexpr uint64_t kDefaultLifetimeSeconds = 300;
constexpr uint64_t kMaximumLifetimeSeconds = 86400;

using Options = std::map<std::string, std::vector<std::string>>;

void SecureErase(void* pointer, size_t size) {
  volatile uint8_t* bytes = static_cast<volatile uint8_t*>(pointer);
  while (size-- != 0) *bytes++ = 0;
}

void PrintUsage(std::ostream& output) {
  output
      << "usage:\n"
      << "  quietproof challenge create --network NETWORK --verifier ID "
         "--purpose PURPOSE --message TEXT (--address ADDRESS | --claim "
         "TXID:VOUT:SATOSHIS:PROGRAM [--claim ...]) --output REQUEST\n"
      << "  quietproof utxos --network NETWORK --address ADDRESS [RPC OPTIONS]\n"
      << "  quietproof prove --request REQUEST --output PROOF [--network NETWORK] [RPC OPTIONS] [--rpc-wallet NAME] [--address ADDRESS]\n"
      << "  quietproof verify PROOF --verifier ID "
         "--purpose PURPOSE --nonce-store FILE [--min-confirmations N] "
         "[--minimum-total-sats N] [--max-lifetime SECONDS] [--network NETWORK]\n"
      << "    Native RPC is default; --bitcoin-cli /ABSOLUTE/PATH explicitly "
         "selects the deprecated legacy verifier.\n"
      << "  quietproof inspect FILE\n"
      << "networks: mainnet, testnet3 (alias testnet), testnet4, signet, regtest\n"
      << "RPC OPTIONS: --rpc-url URL --rpc-cookie FILE --rpc-datadir DIR "
         "--rpc-timeout SECONDS --rpc-scan-timeout SECONDS --rpc-wallet NAME\n"
      << "Discovery: --min-confirmations N (default 1); scan timeout defaults "
         "to 600 seconds. Wallet discovery requires an already loaded wallet.\n";
}

int Usage() {
  PrintUsage(std::cerr);
  return kUsage;
}

bool ParseOptions(int argc, char** argv, int begin,
                  const std::set<std::string>& allowed, Options* options) {
  if (options == nullptr) return false;
  options->clear();
  for (int index = begin; index < argc; index += 2) {
    const std::string name = argv[index];
    if (name.rfind("--", 0) != 0 || !allowed.count(name) || index + 1 >= argc)
      return false;
    (*options)[name].emplace_back(argv[index + 1]);
  }
  return true;
}

bool One(const Options& options, const std::string& name, std::string* value,
         bool required = true) {
  const auto found = options.find(name);
  if (found == options.end()) return !required;
  if (value == nullptr || found->second.size() != 1) return false;
  *value = found->second.front();
  return true;
}

bool ParseU64(const std::string& text, uint64_t* value) {
  if (value == nullptr || text.empty()) return false;
  uint64_t parsed = 0;
  for (char digit : text) {
    if (digit < '0' || digit > '9' ||
        parsed > (std::numeric_limits<uint64_t>::max() -
                  static_cast<uint64_t>(digit - '0')) / 10) return false;
    parsed = parsed * 10 + static_cast<uint64_t>(digit - '0');
  }
  *value = parsed;
  return true;
}

int HexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

template <size_t N>
bool HexArray(const std::string& hex, std::array<uint8_t, N>* output) {
  if (output == nullptr || hex.size() != N * 2) return false;
  for (size_t index = 0; index < N; ++index) {
    const int high = HexNibble(hex[index * 2]);
    const int low = HexNibble(hex[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    (*output)[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

template <size_t N>
std::string ArrayHex(const std::array<uint8_t, N>& value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(N * 2);
  for (uint8_t byte : value) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 15]);
  }
  return output;
}

bool ParseClaim(const std::string& text, proofs::QuietProofClaimV1* claim) {
  if (claim == nullptr) return false;
  std::array<std::string, 4> fields;
  size_t begin = 0;
  for (size_t index = 0; index < fields.size(); ++index) {
    const size_t separator = text.find(':', begin);
    if ((index + 1 < fields.size() && separator == std::string::npos) ||
        (index + 1 == fields.size() && separator != std::string::npos)) return false;
    fields[index] = text.substr(begin, separator - begin);
    begin = separator == std::string::npos ? text.size() : separator + 1;
  }
  uint64_t vout = 0, amount = 0;
  proofs::QuietProofClaimV1 parsed;
  if (!HexArray(fields[0], &parsed.txid) || !ParseU64(fields[1], &vout) ||
      vout > std::numeric_limits<uint32_t>::max() ||
      !ParseU64(fields[2], &amount) || amount == 0 ||
      amount > proofs::kQuietProofMaxMoneySats ||
      !HexArray(fields[3], &parsed.program)) return false;
  parsed.vout = static_cast<uint32_t>(vout);
  parsed.amount_sats = amount;
  *claim = parsed;
  return true;
}

bool ReadBounded(const std::string& path, size_t maximum,
                 std::vector<uint8_t>* output) {
  if (output == nullptr) return false;
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;
  output->clear();
  std::array<char, 8192> buffer{};
  while (stream) {
    stream.read(buffer.data(), buffer.size());
    const std::streamsize count = stream.gcount();
    if (count < 0 || static_cast<size_t>(count) > maximum - output->size()) {
      output->clear();
      return false;
    }
    output->insert(output->end(), buffer.data(), buffer.data() + count);
  }
  return stream.eof();
}

// This preflight avoids expensive work. The atomic writer still enforces
// no replacement if another process creates the destination afterward.
bool CheckNewOutputPath(const std::string& path) {
  struct stat status {};
  if (lstat(path.c_str(), &status) == 0) {
    std::cerr << "Output destination already exists\n";
    return false;
  }
  if (path.empty() || errno != ENOENT) {
    std::cerr << "Cannot inspect output destination\n";
    return false;
  }
  return true;
}

bool WriteAll(int descriptor, const uint8_t* bytes, size_t size) {
  while (size != 0) {
    const ssize_t written = write(descriptor, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    bytes += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

bool WriteNewFileAtomic(const std::string& path,
                        const std::vector<uint8_t>& bytes) {
  if (path.empty()) return false;
  std::array<uint8_t, 8> random_suffix{};
  if (randombytes(random_suffix.data(), random_suffix.size()) != 0) return false;
  const std::string temporary = path + ".tmp." + std::to_string(getpid()) + "." +
                                ArrayHex(random_suffix);
  const int descriptor =
      open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) return false;
  const bool written = WriteAll(descriptor, bytes.data(), bytes.size()) &&
                       fsync(descriptor) == 0;
  const int close_result = close(descriptor);
  if (!written || close_result != 0 || link(temporary.c_str(), path.c_str()) != 0) {
    (void)unlink(temporary.c_str());
    return false;
  }
  (void)unlink(temporary.c_str());
  const size_t separator = path.find_last_of('/');
  const std::string directory = separator == std::string::npos
                                    ? "."
                                    : separator == 0 ? "/" : path.substr(0, separator);
  const int directory_descriptor =
      open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  const bool durable = directory_descriptor >= 0 &&
                       fsync(directory_descriptor) == 0;
  if (directory_descriptor >= 0) (void)close(directory_descriptor);
  if (!durable) (void)unlink(path.c_str());
  return durable;
}

class TerminalEchoGuard {
 public:
  TerminalEchoGuard() {
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original_) != 0) return;
    termios hidden = original_;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
  }
  ~TerminalEchoGuard() {
    if (active_) (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
  }
  TerminalEchoGuard(const TerminalEchoGuard&) = delete;
  TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

 private:
  termios original_{};
  bool active_ = false;
};

bool ReadSecrets(size_t count,
                 std::vector<std::array<uint8_t, 32>>* secrets) {
  if (secrets == nullptr || count == 0 || count > proofs::kQuietProofMaxKeys)
    return false;
  secrets->clear();
  secrets->reserve(count);
  const bool terminal = isatty(STDIN_FILENO);
  if (terminal)
    std::cerr << "Enter " << count << " private key(s), each as 64 hexadecimal characters.\n"
              << "Input is hidden; paste a key and press Enter (not an address).\n";
  TerminalEchoGuard echo_guard;
  for (size_t index = 0; index < count; ++index) {
    if (terminal) std::cerr << "Key " << index + 1 << '/' << count << ": ";
    std::string line;
    const bool read = static_cast<bool>(std::getline(std::cin, line));
    if (terminal) std::cerr << '\n';
    std::array<uint8_t, 32> secret{};
    const bool valid = read && HexArray(line, &secret);
    if (!line.empty()) SecureErase(line.data(), line.size());
    if (!valid) {
      SecureErase(secret.data(), secret.size());
      return false;
    }
    secrets->push_back(secret);
    SecureErase(secret.data(), secret.size());
  }
  return true;
}

void EraseSecrets(std::vector<std::array<uint8_t, 32>>* secrets) {
  if (secrets == nullptr) return;
  for (auto& secret : *secrets) SecureErase(secret.data(), secret.size());
  secrets->clear();
}

int PrintResult(const proofs::QuietProofVerification& verification) {
  nlohmann::json output = {
      {"result", proofs::QuietProofVerifyResultName(verification.result)},
      {"exit_code", proofs::QuietProofVerifyExitCode(verification.result)},
      {"total_sats", verification.total_sats},
      {"claims_checked", verification.claims.size()},
  };
  std::cout << output.dump() << '\n';
  return proofs::QuietProofVerifyExitCode(verification.result);
}

const std::set<std::string> kRpcOptions = {
    "--rpc-url", "--rpc-cookie", "--rpc-datadir", "--rpc-timeout"};
const std::set<std::string> kDiscoveryOptions = {
    "--address", "--min-confirmations", "--rpc-scan-timeout", "--rpc-wallet"};

bool HasDiscoveryOptions(const Options& options) {
  for (const auto& name : kRpcOptions)
    if (options.count(name)) return true;
  for (const auto& name : kDiscoveryOptions)
    if (options.count(name)) return true;
  return false;
}

#ifdef QUIETPROOF_HAS_RPC
// Parse seconds without overflowing the signed milliseconds representation.
bool ParseTimeout(const std::string& text, std::chrono::milliseconds* value) {
  uint64_t seconds = 0;
  if (!ParseU64(text, &seconds) || seconds == 0 ||
      seconds > static_cast<uint64_t>(
                    std::numeric_limits<std::chrono::milliseconds::rep>::max()) /
                    1000) return false;
  *value = std::chrono::milliseconds(seconds * 1000);
  return true;
}

bool ParseRpcOptions(const Options& options, proofs::BitcoinCoreRpcConfig* config) {
  if (!One(options, "--rpc-url", &config->rpc_url, false) ||
      !One(options, "--rpc-cookie", &config->rpc_cookie, false) ||
      !One(options, "--rpc-datadir", &config->rpc_datadir, false)) return false;
  for (const auto& name : kRpcOptions) {
    if (options.count(name) && options.at(name).front().empty()) return false;
  }
  std::string timeout;
  return One(options, "--rpc-timeout", &timeout, false) &&
         (!options.count("--rpc-timeout") || ParseTimeout(timeout, &config->rpc_timeout));
}

const char* RpcErrorName(proofs::BitcoinRpcErrorCode code) {
  using E = proofs::BitcoinRpcErrorCode;
  switch (code) {
    case E::kNone: return "none";
    case E::kConfiguration: return "configuration";
    case E::kCookie: return "cookie";
    case E::kAuthentication: return "authentication";
    case E::kConnection: return "connection";
    case E::kTimeout: return "timeout";
    case E::kResponseTooLarge: return "response_too_large";
    case E::kHttp: return "http";
    case E::kRpc: return "rpc";
    case E::kMalformed: return "malformed";
    case E::kWrongNetwork: return "wrong_network";
    case E::kInvalidAddress: return "invalid_address";
    case E::kUnsupportedScript: return "unsupported_script";
    case E::kScanBusy: return "scan_busy";
    case E::kScanIncomplete: return "scan_incomplete";
    case E::kInconclusive: return "inconclusive";
  }
  return "unknown";
}

int Discover(const Options& options, proofs::QuietProofNetwork network,
             proofs::BitcoinUtxoDiscovery* found) {
  proofs::BitcoinCoreRpcConfig config(network);
  proofs::BitcoinUtxoQuery query;
  std::string confirmations, scan_timeout, wallet;
  if (!ParseRpcOptions(options, &config) ||
      !One(options, "--address", &query.address) || query.address.empty() ||
      !One(options, "--min-confirmations", &confirmations, false) ||
      !One(options, "--rpc-scan-timeout", &scan_timeout, false) ||
      !One(options, "--rpc-wallet", &wallet, false) ||
      (options.count("--min-confirmations") &&
       (!ParseU64(confirmations, &query.min_confirmations) || query.min_confirmations == 0)) ||
      (options.count("--rpc-scan-timeout") && !ParseTimeout(scan_timeout, &config.scan_timeout)))
    return Usage();
  if (options.count("--rpc-wallet")) {
    if (wallet.empty()) return Usage();
    query.wallet = wallet;
  } else {
    std::cerr << "Scanning Core's whole UTXO set; this may take minutes and "
                 "uses the node-global scan. A timeout may leave it running; "
                 "QuietProof does not retry or abort scans.\n";
  }
  proofs::BitcoinCoreRpc bitcoin(std::move(config));
  proofs::BitcoinRpcError error;
  if (bitcoin.Discover(query, found, &error)) return 0;
  std::cerr << nlohmann::json({{"error", RpcErrorName(error.code)},
                              {"message", error.message}}).dump() << '\n';
  using E = proofs::BitcoinRpcErrorCode;
  if (error.code == E::kConfiguration) return kUsage;
  if (error.code == E::kInvalidAddress || error.code == E::kUnsupportedScript ||
      error.code == E::kMalformed || error.code == E::kWrongNetwork) return kData;
  return kIoError;
}
#endif

#ifndef QUIETPROOF_HAS_RPC
int NativeUnavailable() {
  std::cerr << "{\"error\":\"native_unavailable\",\"message\":\"Native Bitcoin Core RPC "
               "support is unavailable in this build\"}\n";
  return kUsage;
}
#endif

int Utxos(int argc, char** argv) {
  auto allowed = kRpcOptions;
  allowed.insert(kDiscoveryOptions.begin(), kDiscoveryOptions.end());
  allowed.insert("--network");
  Options options;
  std::string network_name;
  proofs::QuietProofNetwork network;
  if (!ParseOptions(argc, argv, 2, allowed, &options) ||
      !One(options, "--network", &network_name) ||
      !proofs::QuietProofParseNetwork(network_name, &network)) return Usage();
#ifdef QUIETPROOF_HAS_RPC
  proofs::BitcoinUtxoDiscovery found;
  const int status = Discover(options, network, &found);
  if (status != 0) return status;
  nlohmann::json outputs = nlohmann::json::array();
  for (const auto& output : found.outputs) {
    outputs.push_back({{"txid", ArrayHex(output.claim.txid)},
                       {"vout", output.claim.vout},
                       {"amount_sats", output.claim.amount_sats},
                       {"program", ArrayHex(output.claim.program)},
                       {"confirmations", output.confirmations}});
  }
  nlohmann::json result = {
      {"network", proofs::QuietProofNetworkName(found.network)},
      {"source", options.count("--rpc-wallet") ? "wallet" : "scan"},
      {"outputs", outputs}, {"count", found.outputs.size()},
      {"excluded_below_min_confirmations", found.excluded_below_min_confirmations},
      {"observed_block", ArrayHex(found.observed_block)},
      {"observed_height", found.observed_height},
      {"scan_block", found.scan_block ? nlohmann::json(ArrayHex(*found.scan_block)) : nlohmann::json(nullptr)},
      {"scan_height", found.scan_height ? nlohmann::json(*found.scan_height) : nlohmann::json(nullptr)},
      {"current_rechecked", found.current_rechecked},
      {"challenge_compatible", found.challenge_compatible},
      {"incompatibility", found.incompatibility}};
  std::cout << result.dump() << '\n';
  return 0;
#else
  return NativeUnavailable();
#endif
}

int ChallengeCreate(int argc, char** argv) {
  std::set<std::string> allowed = {
      "--network", "--verifier", "--purpose", "--message", "--claim",
      "--output", "--expires-in"};
  allowed.insert(kRpcOptions.begin(), kRpcOptions.end());
  allowed.insert(kDiscoveryOptions.begin(), kDiscoveryOptions.end());
  Options options;
  if (!ParseOptions(argc, argv, 3, allowed, &options)) return Usage();
  std::string network_name, verifier, purpose, message, output_path,
      lifetime_text;
  if (!One(options, "--network", &network_name) ||
      !One(options, "--verifier", &verifier) ||
      !One(options, "--purpose", &purpose) ||
      !One(options, "--message", &message) ||
      !One(options, "--output", &output_path) ||
      !One(options, "--expires-in", &lifetime_text, false)) return Usage();
  if (!CheckNewOutputPath(output_path)) return kIoError;
  uint64_t lifetime = kDefaultLifetimeSeconds;
  if (!lifetime_text.empty() && !ParseU64(lifetime_text, &lifetime)) return Usage();
  if (lifetime == 0 || lifetime > kMaximumLifetimeSeconds) return Usage();
  const auto claims = options.find("--claim");
  const bool address_mode = options.count("--address") != 0;
  if (address_mode == (claims != options.end())) return Usage();
  if (!address_mode && (HasDiscoveryOptions(options) || claims->second.empty() ||
      claims->second.size() > proofs::kQuietProofMaxClaims)) return Usage();

  proofs::QuietProofChallengeOptions challenge_options;
  if (!proofs::QuietProofParseNetwork(network_name, &challenge_options.network))
    return Usage();
  challenge_options.verifier = verifier;
  challenge_options.purpose = purpose;
  challenge_options.message = message;
  challenge_options.lifetime_seconds = lifetime;
  std::vector<proofs::QuietProofClaimV1> parsed_claims;
  if (address_mode) {
#ifdef QUIETPROOF_HAS_RPC
    proofs::BitcoinUtxoDiscovery found;
    const int status = Discover(options, challenge_options.network, &found);
    if (status != 0) return status;
    if (!found.challenge_compatible || !found.current_rechecked) {
      const char* category = found.outputs.empty() ? "no_eligible_outputs"
                                                   : "incompatible_discovery";
      std::cerr << nlohmann::json({{"error", category},
                                  {"message", found.incompatibility}}).dump() << '\n';
      return kData;
    }
    for (const auto& output : found.outputs) parsed_claims.push_back(output.claim);
#else
    return NativeUnavailable();
#endif
  } else {
    for (const auto& encoded_claim : claims->second) {
      proofs::QuietProofClaimV1 claim;
      if (!ParseClaim(encoded_claim, &claim)) return Usage();
      parsed_claims.push_back(claim);
    }
  }
  proofs::QuietProofStatementV1 statement;
  proofs::QuietProofChallengeError error;
  if (!proofs::CreateQuietProofChallenge(parsed_claims, challenge_options,
                                        &statement, &error)) {
    if (error == proofs::QuietProofChallengeError::kClock ||
        error == proofs::QuietProofChallengeError::kRandom) return kIoError;
    std::cerr << "challenge violates the QuietProof v1 statement contract\n";
    return kData;
  }
  std::vector<uint8_t> request;
  if (!proofs::EncodeQuietProofStatement(statement, &request)) {
    std::cerr << "challenge violates the QuietProof v1 statement contract\n";
    return kData;
  }
  if (!WriteNewFileAtomic(output_path, request)) {
    std::cerr << "could not create request file (the destination must not exist)\n";
    return kIoError;
  }
  nlohmann::json result = {{"result", "challenge_created"},
                           {"request", output_path},
                           {"network", proofs::QuietProofNetworkName(statement.network)},
                           {"expires_at", statement.expires_at},
                           {"claims", statement.claims.size()}};
  std::cout << result.dump() << '\n';
  return 0;
}

int Prove(int argc, char** argv) {
  Options options;
  auto allowed = kRpcOptions;
  allowed.insert({"--request", "--output", "--rpc-wallet", "--address", "--network"});
  if (!ParseOptions(argc, argv, 2, allowed, &options))
    return Usage();
  std::string request_path, output_path;
  if (!One(options, "--request", &request_path) ||
      !One(options, "--output", &output_path)) return Usage();
  if (!CheckNewOutputPath(output_path)) return kIoError;
  std::vector<uint8_t> request;
  proofs::QuietProofStatementV1 statement;
  proofs::QuietProofDecodeError error = proofs::QuietProofDecodeError::kMalformed;
  if (!ReadBounded(request_path, proofs::kQuietProofMaxStatementBytes, &request) ||
      !proofs::DecodeQuietProofStatement(request, &statement, &error)) {
    std::cerr << "invalid or unsupported QuietProof request\n";
    return kData;
  }
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (now < 0 || static_cast<uint64_t>(now) < statement.not_before ||
      static_cast<uint64_t>(now) >= statement.expires_at) {
    std::cerr << "QuietProof request is not currently valid\n";
    return kData;
  }
  std::vector<std::array<uint8_t, 20>> programs;
  if (!proofs::QuietProofDistinctPrograms(statement, &programs)) return kData;
  std::vector<std::array<uint8_t, 32>> secrets;
  if (options.count("--network")) {
    std::string network_name;
    proofs::QuietProofNetwork network;
    if (!One(options, "--network", &network_name) ||
        !proofs::QuietProofParseNetwork(network_name, &network)) return Usage();
    if (network != statement.network) {
      std::cerr << "Network does not match the request\n";
      return kData;
    }
  }
  bool wallet_mode = options.count("--rpc-wallet") || options.count("--address");
  for (const auto& option : kRpcOptions) wallet_mode |= options.count(option) != 0;
  if (wallet_mode) {
#ifdef QUIETPROOF_HAS_RPC
    std::string wallet, address;
    proofs::BitcoinCoreRpcConfig config(statement.network);
    if (!One(options, "--rpc-wallet", &wallet, false) ||
        !One(options, "--address", &address, false) || !ParseRpcOptions(options, &config)) return Usage();
    if (programs.size() != 1) {
      std::cerr << "Wallet export requires a request with one distinct P2WPKH address; use stdin for multiple keys.\n";
      return kData;
    }
    proofs::BitcoinCoreRpc rpc(std::move(config));
    proofs::BitcoinRpcError rpc_error;
    secrets.resize(1);
    if (!rpc.ExportAddressKey(wallet, address, programs.front(), &secrets.front(), &rpc_error)) {
      EraseSecrets(&secrets);
      std::cerr << rpc_error.message << '\n';
      return kData;
    }
#else
    return NativeUnavailable();
#endif
  } else if (!ReadSecrets(programs.size(), &secrets)) {
    EraseSecrets(&secrets);
    std::cerr << "Invalid key input: expected 64 hexadecimal characters per private key, not an address.\n";
    return kData;
  }
  std::cerr << "Key input received. Checking keys against the request...\n";
  std::vector<std::array<uint8_t, 20>> supplied_programs;
  for (const auto& secret : secrets) {
    proofs::PoKCWitnessV1<proofs::PoKCField, proofs::PoKCEC> witness;
    const bool valid = witness.compute(proofs::p256k1, secret.data(), secret.size());
    if (valid) supplied_programs.push_back(witness.program());
    SecureErase(&witness, sizeof(witness));
    if (!valid) {
      EraseSecrets(&secrets);
      std::cerr << "Invalid private key: scalar must be nonzero and below the secp256k1 order.\n";
      return kData;
    }
  }
  std::sort(supplied_programs.begin(), supplied_programs.end());
  std::sort(programs.begin(), programs.end());
  if (supplied_programs != programs) {
    EraseSecrets(&secrets);
    std::cerr << "Private keys do not match the request; provide one key per distinct address.\n";
    return kData;
  }
  std::cerr << "Keys validated. Generating proof; this may take several minutes...\n";
  proofs::QuietProofEnvelopeV1 envelope;
  bool proved = false;
  {
    quietproof_cli::ProofProgress progress(std::cerr);
    const auto phase = [&progress](const char* name) { progress.SetPhase(name); };
    if (programs.size() == 1)
      proved = proofs::PoKCProveKeys<1>(secrets, statement, &envelope, phase);
    else if (programs.size() == 2)
      proved = proofs::PoKCProveKeys<2>(secrets, statement, &envelope, phase);
  }
  EraseSecrets(&secrets);
  std::vector<uint8_t> wire;
  if (!proved || !proofs::EncodeQuietProofEnvelope(envelope, &wire)) {
    std::cerr << "proof generation failed\n";
    return 2;
  }
  if (!WriteNewFileAtomic(output_path, wire)) {
    std::cerr << "could not create proof file (the destination must not exist)\n";
    return kIoError;
  }
  std::cout << nlohmann::json({{"result", "proof_created"},
                               {"proof", output_path},
                               {"proof_bytes", envelope.proof.bytes.size()}}).dump()
            << '\n';
  return 0;
}

int Verify(int argc, char** argv) {
  if (argc < 3) return Usage();
  const std::string proof_path = argv[2];
  Options options;
  auto allowed = kRpcOptions;
  allowed.insert({"--bitcoin-cli", "--verifier", "--purpose", "--nonce-store",
                  "--min-confirmations", "--minimum-total-sats",
                  "--max-lifetime", "--network"});
  if (!ParseOptions(argc, argv, 3, allowed, &options)) return Usage();
  std::string executable, verifier, purpose, nonce_store, confirmations_text,
      minimum_text, lifetime_text, network_name;
  if (!One(options, "--bitcoin-cli", &executable, false) ||
      !One(options, "--verifier", &verifier) ||
      !One(options, "--purpose", &purpose) ||
      !One(options, "--nonce-store", &nonce_store) ||
      !One(options, "--min-confirmations", &confirmations_text, false) ||
      !One(options, "--minimum-total-sats", &minimum_text, false) ||
      !One(options, "--max-lifetime", &lifetime_text, false) ||
      !One(options, "--network", &network_name, false)) return Usage();
  const bool legacy = options.count("--bitcoin-cli") != 0;
  if (legacy) {
    if (executable.empty() || executable[0] != '/' ||
        access(executable.c_str(), X_OK) != 0) return Usage();
    for (const auto& name : kRpcOptions)
      if (options.count(name)) return Usage();
    std::cerr << "--bitcoin-cli selects the deprecated legacy backend; "
                 "use native Bitcoin Core RPC for new integrations.\n";
  }
  proofs::QuietProofNetwork asserted_network;
  if (options.count("--network") &&
      !proofs::QuietProofParseNetwork(network_name, &asserted_network)) return Usage();
#ifndef QUIETPROOF_HAS_RPC
  if (!legacy) return NativeUnavailable();
#endif
  uint64_t min_confirmations = 1, minimum_total = 0,
           max_lifetime = kMaximumLifetimeSeconds;
  if ((!confirmations_text.empty() &&
       !ParseU64(confirmations_text, &min_confirmations)) ||
      (!minimum_text.empty() && !ParseU64(minimum_text, &minimum_total)) ||
      (!lifetime_text.empty() && !ParseU64(lifetime_text, &max_lifetime)) ||
      minimum_total > proofs::kQuietProofMaxMoneySats || max_lifetime == 0 ||
      max_lifetime > kMaximumLifetimeSeconds) return Usage();

  std::vector<uint8_t> wire;
  if (!ReadBounded(proof_path, proofs::kQuietProofMaxEnvelopeBytes, &wire))
    return PrintResult({proofs::QuietProofVerifyResult::kMalformedStatement, {}});
  proofs::QuietProofEnvelopeV1 envelope;
  proofs::QuietProofDecodeError error = proofs::QuietProofDecodeError::kMalformed;
  if (!proofs::DecodeQuietProofEnvelope(wire, &envelope, &error))
    return PrintResult({error == proofs::QuietProofDecodeError::kUnsupported
                            ? proofs::QuietProofVerifyResult::kUnsupported
                            : proofs::QuietProofVerifyResult::kMalformedStatement,
                        {}});
  if (options.count("--network") && asserted_network != envelope.statement.network) {
    std::cerr << "{\"error\":\"wrong_network\",\"message\":\"Proof network does not "
                 "match the local network policy\"}\n";
    return PrintResult({proofs::QuietProofVerifyResult::kInvalidProof, {}});
  }
  std::unique_ptr<proofs::QuietProofChainProvider> provider;
  if (legacy) {
    provider = std::make_unique<proofs::BitcoinCoreCurrentTipProvider>(
        executable, envelope.statement.network);
  } else {
#ifdef QUIETPROOF_HAS_RPC
    proofs::BitcoinCoreRpcConfig rpc_config(envelope.statement.network);
    if (!ParseRpcOptions(options, &rpc_config)) return Usage();
    provider = std::make_unique<proofs::BitcoinCoreRpc>(std::move(rpc_config));
#endif
  }
  std::cerr << "Bitcoin Core verification network: "
            << proofs::QuietProofNetworkName(envelope.statement.network) << '\n';
  proofs::QuietProofVerifierConfig config;
  config.provider = provider.get();
  config.supports = [](const proofs::QuietProofEnvelopeV1& candidate) {
    return proofs::PoKCProofSupported(candidate);
  };
  config.verify_proof = [](const proofs::QuietProofEnvelopeV1& candidate) {
    return proofs::PoKCVerifyProof(candidate);
  };
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (now < 0) {
    std::cerr << "system clock is outside the supported range\n";
    return kIoError;
  }
  config.policy.now = static_cast<uint64_t>(now);
  config.policy.max_lifetime = max_lifetime;
  config.policy.verifier = verifier;
  config.policy.purpose = purpose;
  config.policy.consume_nonce = [&nonce_store](const std::array<uint8_t, 32>& nonce) {
    return proofs::QuietProofConsumeNonceFile(nonce_store, nonce);
  };
  config.min_confirmations = min_confirmations;
  config.minimum_total_sats = minimum_total;
  const auto verification = proofs::VerifyQuietProof(wire, config);
  if (!legacy && verification.result == proofs::QuietProofVerifyResult::kStateInconclusive)
    std::cerr << "{\"error\":\"chain_state_inconclusive\",\"message\":\"Native Bitcoin "
                 "Core RPC could not establish the required chain evidence\"}\n";
  return PrintResult(verification);
}

int Inspect(const std::string& path) {
  std::vector<uint8_t> bytes;
  if (!ReadBounded(path, proofs::kQuietProofMaxEnvelopeBytes, &bytes)) return kData;
  proofs::QuietProofEnvelopeV1 envelope;
  if (proofs::DecodeQuietProofEnvelope(bytes, &envelope)) {
    std::cout << proofs::QuietProofInspectJson(envelope) << '\n';
    return 0;
  }
  proofs::QuietProofStatementV1 statement;
  if (!proofs::DecodeQuietProofStatement(bytes, &statement)) return kData;
  nlohmann::json output = {{"format", "quietproof-request-v1"},
                           {"network", proofs::QuietProofNetworkName(statement.network)},
                           {"verifier", statement.verifier},
                           {"purpose", statement.purpose},
                           {"not_before", statement.not_before},
                           {"expires_at", statement.expires_at},
                           {"claims", statement.claims.size()},
                           {"has_snapshot", statement.has_snapshot}};
  std::cout << output.dump() << '\n';
  return 0;
}

}  // namespace

int QuietProofMain(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--help") {
    std::cout << "QuietProof — prove you control bitcoin without revealing your public key.\n";
    PrintUsage(std::cout);
    return 0;
  }
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--secret" || argument.rfind("--secret=", 0) == 0) {
      std::cerr << "secret material is accepted only from protected stdin\n";
      return kUsage;
    }
  }
  if (argc >= 3 && std::string(argv[1]) == "challenge" &&
      std::string(argv[2]) == "create") return ChallengeCreate(argc, argv);
  if (argc >= 2 && std::string(argv[1]) == "utxos") return Utxos(argc, argv);
  if (argc >= 2 && std::string(argv[1]) == "prove") return Prove(argc, argv);
  if (argc >= 3 && std::string(argv[1]) == "verify") return Verify(argc, argv);
  if (argc == 3 && std::string(argv[1]) == "inspect") return Inspect(argv[2]);
  return Usage();
}

int main(int argc, char** argv) {
  try {
    return QuietProofMain(argc, argv);
  } catch (const std::exception& exception) {
    std::cerr << "fatal QuietProof error: " << exception.what() << '\n';
  } catch (...) {
    std::cerr << "fatal QuietProof error\n";
  }
  return kSoftware;
}
