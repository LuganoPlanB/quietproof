// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Build with the installed LongfellowZKQuietProof rpc component. This example's
// verifier policy is deliberately local and fixed: example.org / proof-of-funds,
// lifetime at most 300 seconds, at least one confirmation. Adapt it in your app.
// Commands exchange existing binary requests/proofs, so prove can run offline.
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "quietproof/bitcoin_rpc.h"
#include "quietproof/challenge.h"
#include "quietproof/nonce_store.h"
#include "quietproof/verifier.h"
#include "pokc/prover.h"

namespace {
using namespace proofs;

void Erase(void* memory, size_t size) {
  auto* bytes = static_cast<volatile uint8_t*>(memory);
  while (size-- != 0) *bytes++ = 0;
}

template <size_t N>
std::string Hex(const std::array<uint8_t, N>& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string text;
  for (auto byte : bytes) {
    text += digits[byte >> 4];
    text += digits[byte & 15];
  }
  return text;
}

bool Read(const std::string& path, size_t maximum, std::vector<uint8_t>* out) {
  std::ifstream input(path, std::ios::binary);
  std::array<char, 8192> buffer{};
  while (input) {
    input.read(buffer.data(), buffer.size());
    const auto count = input.gcount();
    if (count < 0 || static_cast<size_t>(count) > maximum - out->size()) return false;
    out->insert(out->end(), buffer.data(), buffer.data() + count);
  }
  return input.eof();
}

// Owner-only, no replacement, durable output: same POSIX pattern as the CLI.
bool WriteNew(const std::string& path, const std::vector<uint8_t>& bytes) {
  std::array<uint8_t, 8> suffix{};
  if (path.empty() || randombytes(suffix.data(), suffix.size()) != 0) return false;
  const std::string temporary = path + ".tmp." + std::to_string(getpid()) + "." + Hex(suffix);
  const int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = write(fd, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) break;
    offset += static_cast<size_t>(count);
  }
  const bool written = offset == bytes.size() && fsync(fd) == 0;
  const int closed = close(fd);
  const bool linked = written && closed == 0 && link(temporary.c_str(), path.c_str()) == 0;
  (void)unlink(temporary.c_str());
  if (!linked) return false;
  const auto slash = path.find_last_of('/');
  const auto directory = slash == std::string::npos ? "." :
                         slash == 0 ? "/" : path.substr(0, slash);
  const int parent = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  const bool durable = parent >= 0 && fsync(parent) == 0;
  if (parent >= 0) (void)close(parent);
  if (!durable) (void)unlink(path.c_str());
  return durable;
}

struct Secret {
  std::vector<std::array<uint8_t, 32>> keys{1};
  std::array<char, 64> text{};
  ~Secret() {
    Erase(text.data(), text.size());
    for (auto& key : keys) Erase(key.data(), key.size());
  }
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
};

class EchoGuard {
 public:
  EchoGuard() {
    if (!isatty(STDIN_FILENO)) { ready_ = true; return; }
    if (tcgetattr(STDIN_FILENO, &original_) != 0) return;
    auto hidden = original_;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
    ready_ = active_;
  }
  ~EchoGuard() {
    if (active_) (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
  }
  bool ready() const { return ready_; }
  EchoGuard(const EchoGuard&) = delete;
  EchoGuard& operator=(const EchoGuard&) = delete;
 private:
  termios original_{};
  bool active_ = false, ready_ = false;
};

bool ReadSecret(Secret* secret) {
  EchoGuard echo;
  if (!echo.ready()) return false;
  if (isatty(STDIN_FILENO)) std::cerr << "Enter one 32-byte hexadecimal key: ";
  size_t size = 0;
  char byte = 0;
  while (true) {
    const auto count = read(STDIN_FILENO, &byte, 1);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) { Erase(&byte, 1); return false; }
    if (count == 0 || byte == '\n') break;
    if (size == secret->text.size()) { Erase(&byte, 1); return false; }
    secret->text[size++] = byte;
  }
  Erase(&byte, 1);
  if (isatty(STDIN_FILENO)) std::cerr << '\n';
  if (size != 64) return false;
  const auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < 32; ++i) {
    const int high = nibble(secret->text[i * 2]);
    const int low = nibble(secret->text[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    secret->keys[0][i] = static_cast<uint8_t>((high << 4) | low);
  }
  Erase(secret->text.data(), secret->text.size());
  return true;
}

int Discover(BitcoinCoreRpc& bitcoin, const std::string& address,
             BitcoinUtxoDiscovery* found) {
  std::cerr << "Scanning the node-global UTXO set; this may take minutes. "
               "A timeout may leave Core scanning; no retry or abort is sent.\n";
  BitcoinRpcError error;
  if (bitcoin.Discover(BitcoinUtxoQuery{address}, found, &error)) return 0;
  std::cerr << "RPC error " << static_cast<int>(error.code) << ": " << error.message << '\n';
  return 74;
}

// Discovery is independent of challenge construction. This step generates time
// and randomness only after discovery/rechecks have completed.
bool BuildChallenge(const BitcoinUtxoDiscovery& found, QuietProofStatementV1* request) {
  if (!found.challenge_compatible || !found.current_rechecked) return false;
  std::vector<QuietProofClaimV1> claims;
  for (const auto& output : found.outputs) claims.push_back(output.claim);
  return CreateQuietProofChallenge(claims, QuietProofChallengeOptions{
      found.network, "example.org", "proof-of-funds", "Proof of control", 300}, request);
}

int Prove(const std::string& request_path, const std::string& proof_path) {
  std::vector<uint8_t> bytes;
  QuietProofStatementV1 request;
  if (!Read(request_path, kQuietProofMaxStatementBytes, &bytes) ||
      !DecodeQuietProofStatement(bytes, &request)) {
    std::cerr << "Invalid or unreadable QuietProof request\n"; return 65;
  }
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  if (now < 0 || static_cast<uint64_t>(now) < request.not_before ||
      static_cast<uint64_t>(now) >= request.expires_at) {
    std::cerr << "Request is not currently valid\n"; return 65;
  }
  std::vector<std::array<uint8_t, 20>> programs;
  if (!QuietProofDistinctPrograms(request, &programs) || programs.size() != 1) {
    std::cerr << "This example supports exactly one key\n"; return 65;
  }
  Secret secret;
  if (!ReadSecret(&secret)) { std::cerr << "Expected one hexadecimal key on protected stdin\n"; return 65; }
  QuietProofEnvelopeV1 proof;
  const bool proved = PoKCProveKeys<1>(secret.keys, request, &proof);
  for (auto& key : secret.keys) Erase(key.data(), key.size());
  if (!proved) { std::cerr << "Proof generation failed\n"; return 67; }
  bytes.clear();
  if (!EncodeQuietProofEnvelope(proof, &bytes)) return 65;
  if (!WriteNew(proof_path, bytes)) {
    std::cerr << "Could not create proof; destination must not exist\n"; return 74;
  }
  std::cout << "proof_created\n";
  return 0;
}

int Verify(BitcoinCoreRpcConfig rpc, const std::string& proof_path,
           const std::string& nonce_file) {
  std::vector<uint8_t> bytes;
  QuietProofEnvelopeV1 proof;
  QuietProofDecodeError error = QuietProofDecodeError::kMalformed;
  if (!Read(proof_path, kQuietProofMaxEnvelopeBytes, &bytes) ||
      !DecodeQuietProofEnvelope(bytes, &proof, &error)) {
    std::cerr << "Invalid, unsupported or unreadable QuietProof envelope\n";
    return error == QuietProofDecodeError::kUnsupported ? 66 : 65;
  }
  if (proof.statement.network != rpc.network) {
    std::cerr << "Proof network differs from local policy\n"; return 67;
  }
  BitcoinCoreRpc bitcoin(std::move(rpc));
  QuietProofVerifierConfig config;
  config.provider = &bitcoin;  // Always fresh Lookup calls; no discovery cache.
  config.supports = PoKCProofSupported;
  config.verify_proof = PoKCVerifyProof;
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  if (now < 0) return 74;
  config.policy.now = static_cast<uint64_t>(now);
  config.policy.verifier = "example.org";
  config.policy.purpose = "proof-of-funds";
  config.policy.max_lifetime = 300;
  config.policy.consume_nonce = [&nonce_file](const auto& nonce) {
    return QuietProofConsumeNonceFile(nonce_file, nonce);
  };
  config.min_confirmations = 1;
  const auto result = VerifyQuietProof(bytes, config);
  std::cout << QuietProofVerifyResultName(result.result) << '\n';
  return QuietProofVerifyExitCode(result.result);
}

int Usage() {
  std::cerr << "Bitcoin RPC example (local policy example.org / proof-of-funds, 300s):\n"
               "  quietproof-rpc-api-driver discover NETWORK ADDRESS [COOKIE [URL]]\n"
               "  quietproof-rpc-api-driver challenge NETWORK ADDRESS REQUEST [COOKIE [URL]]\n"
               "  quietproof-rpc-api-driver prove REQUEST PROOF  # one key via protected stdin\n"
               "  quietproof-rpc-api-driver verify NETWORK PROOF NONCE_FILE [COOKIE [URL]]\n";
  return 64;
}

int Run(int argc, char** argv) {
  if (argc < 2) return Usage();
  const std::string command = argv[1];
  if (command == "prove") return argc == 4 ? Prove(argv[2], argv[3]) : Usage();
  const bool discover = command == "discover";
  const bool challenge = command == "challenge";
  const bool verify = command == "verify";
  const int required = discover ? 4 : 5;
  if ((!discover && !challenge && !verify) || argc < required || argc > required + 2)
    return Usage();
  QuietProofNetwork network;
  if (!QuietProofParseNetwork(argv[2], &network)) return Usage();
  BitcoinCoreRpcConfig rpc(network);
  if (argc > required) rpc.rpc_cookie = argv[required];
  if (argc > required + 1) rpc.rpc_url = argv[required + 1];
  if (verify) return Verify(std::move(rpc), argv[3], argv[4]);
  BitcoinCoreRpc bitcoin(std::move(rpc));
  BitcoinUtxoDiscovery found;
  const int status = Discover(bitcoin, argv[3], &found);
  if (status != 0) return status;
  if (discover) {
    std::cout << "outputs=" << found.outputs.size() << " challenge_compatible="
              << found.challenge_compatible << " reason=" << found.incompatibility << '\n';
    for (const auto& output : found.outputs)
      std::cout << Hex(output.claim.txid) << ':' << output.claim.vout << ':'
                << output.claim.amount_sats << ':' << Hex(output.claim.program) << '\n';
    return 0;
  }
  QuietProofStatementV1 request;
  std::vector<uint8_t> bytes;
  if (!BuildChallenge(found, &request)) {
    std::cerr << (found.incompatibility.empty() ? "Challenge construction failed" :
                                                found.incompatibility) << '\n';
    return 65;
  }
  if (!EncodeQuietProofStatement(request, &bytes)) return 65;
  if (!WriteNew(argv[4], bytes)) {
    std::cerr << "Could not create request; destination must not exist\n"; return 74;
  }
  std::cout << "challenge_created\n";
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  try { return Run(argc, argv); }
  catch (...) { std::cerr << "Bitcoin RPC example failed\n"; return 74; }
}
