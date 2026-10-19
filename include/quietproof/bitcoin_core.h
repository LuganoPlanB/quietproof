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
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_BITCOIN_CORE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_BITCOIN_CORE_H_

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <initializer_list>
#include <poll.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "quietproof/chain_state.h"
#include "quietproof/detail/bitcoin_core_parse.h"

namespace proofs {

constexpr std::chrono::seconds kQuietProofRpcTimeout{30};

struct QuietProofProcessResult {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
  bool timed_out = false;
  bool output_limit_exceeded = false;
};

namespace quietproof_internal {

class FileDescriptor {
 public:
  FileDescriptor() = default;
  explicit FileDescriptor(int descriptor) : descriptor_(descriptor) {}
  ~FileDescriptor() { reset(); }
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  FileDescriptor(FileDescriptor&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) reset(std::exchange(other.descriptor_, -1));
    return *this;
  }
  int get() const { return descriptor_; }
  explicit operator bool() const { return descriptor_ >= 0; }
  int release() { return std::exchange(descriptor_, -1); }
  void reset(int descriptor = -1) {
    if (descriptor_ >= 0) {
      while (close(descriptor_) < 0 && errno == EINTR) {}
    }
    descriptor_ = descriptor;
  }

 private:
  int descriptor_ = -1;
};

inline bool MakePipe(FileDescriptor* read_end, FileDescriptor* write_end) {
  if (read_end == nullptr || write_end == nullptr) return false;
  int descriptors[2] = {-1, -1};
  if (pipe(descriptors) != 0) return false;
  read_end->reset(descriptors[0]);
  write_end->reset(descriptors[1]);
  for (int descriptor : descriptors) {
    const int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) return false;
  }
  return true;
}

inline bool SetNonBlocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

inline void KillProcessGroup(pid_t child) {
  // The parent and child both attempt setpgid. The direct kill is a fallback
  // for the narrow race where process-group creation was not possible.
  (void)kill(-child, SIGKILL);
  (void)kill(child, SIGKILL);
}

inline bool AppendAvailable(FileDescriptor* descriptor, std::string* output,
                            bool* limit_exceeded) {
  if (descriptor == nullptr || output == nullptr || limit_exceeded == nullptr)
    return false;
  std::array<char, 4096> buffer{};
  while (*descriptor) {
    const ssize_t count = read(descriptor->get(), buffer.data(), buffer.size());
    if (count > 0) {
      const size_t available = kQuietProofMaxRpcOutputBytes -
                               std::min(output->size(), kQuietProofMaxRpcOutputBytes);
      if (static_cast<size_t>(count) > available) {
        output->append(buffer.data(), available);
        *limit_exceeded = true;
        return false;
      }
      output->append(buffer.data(), static_cast<size_t>(count));
      continue;
    }
    if (count == 0) {
      descriptor->reset();
      return true;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    descriptor->reset();
    return false;
  }
  return true;
}

// Bitcoin Core emits the top-level `value` field as a JSON decimal in BTC.
// Keep its original token so no IEEE-754 conversion can move the amount by a
// satoshi. The full response is independently parsed as JSON before this runs.
inline bool TopLevelNumberToken(const std::string& json, const std::string& key,
                                std::string* token) {
  if (token == nullptr) return false;
  size_t depth = 0;
  bool found = false;
  for (size_t index = 0; index < json.size();) {
    const char current = json[index];
    if (current == '{' || current == '[') {
      ++depth;
      ++index;
      continue;
    }
    if (current == '}' || current == ']') {
      if (depth == 0) return false;
      --depth;
      ++index;
      continue;
    }
    if (current != '"') {
      ++index;
      continue;
    }
    const size_t begin = ++index;
    bool escaped = false;
    while (index < json.size()) {
      if (!escaped && json[index] == '"') break;
      if (!escaped && json[index] == '\\') {
        escaped = true;
      } else {
        escaped = false;
      }
      ++index;
    }
    if (index == json.size()) return false;
    const std::string candidate = json.substr(begin, index - begin);
    ++index;
    if (depth != 1 || candidate != key) continue;
    if (found) return false;
    while (index < json.size() &&
           (json[index] == ' ' || json[index] == '\t' || json[index] == '\r' ||
            json[index] == '\n')) ++index;
    if (index == json.size() || json[index] != ':') return false;
    ++index;
    while (index < json.size() &&
           (json[index] == ' ' || json[index] == '\t' || json[index] == '\r' ||
            json[index] == '\n')) ++index;
    const size_t number_begin = index;
    while (index < json.size() && json[index] != ',' && json[index] != '}' &&
           json[index] != ' ' && json[index] != '\t' && json[index] != '\r' &&
           json[index] != '\n') ++index;
    if (number_begin == index) return false;
    *token = json.substr(number_begin, index - number_begin);
    found = true;
  }
  return found;
}

}  // namespace quietproof_internal

inline QuietProofProcessResult QuietProofRunArgv(
    const std::vector<std::string>& argv) {
  QuietProofProcessResult result;
  if (argv.empty() || argv.front().empty() || argv.front()[0] != '/') return result;

  quietproof_internal::FileDescriptor stdout_read, stdout_write, stderr_read,
      stderr_write;
  if (!quietproof_internal::MakePipe(&stdout_read, &stdout_write) ||
      !quietproof_internal::MakePipe(&stderr_read, &stderr_write)) return result;

  const pid_t child = fork();
  if (child == 0) {
    (void)setpgid(0, 0);
    stdout_read.reset();
    stderr_read.reset();
    if (dup2(stdout_write.get(), STDOUT_FILENO) < 0 ||
        dup2(stderr_write.get(), STDERR_FILENO) < 0) _exit(126);
    stdout_write.reset();
    stderr_write.reset();
    std::vector<char*> arguments;
    arguments.reserve(argv.size() + 1);
    for (const auto& value : argv)
      arguments.push_back(const_cast<char*>(value.c_str()));
    arguments.push_back(nullptr);
    execv(arguments.front(), arguments.data());
    _exit(errno == ENOENT ? 127 : 126);
  }
  stdout_write.reset();
  stderr_write.reset();
  if (child < 0) return result;
  (void)setpgid(child, child);
  if (!quietproof_internal::SetNonBlocking(stdout_read.get()) ||
      !quietproof_internal::SetNonBlocking(stderr_read.get())) {
    quietproof_internal::KillProcessGroup(child);
    (void)waitpid(child, nullptr, 0);
    return result;
  }

  const auto deadline = std::chrono::steady_clock::now() + kQuietProofRpcTimeout;
  int status = 0;
  bool child_reaped = false;
  bool child_status_available = false;
  while (stdout_read || stderr_read || !child_reaped) {
    if (!result.timed_out && std::chrono::steady_clock::now() >= deadline) {
      result.timed_out = true;
      if (!child_reaped) quietproof_internal::KillProcessGroup(child);
    }
    std::array<pollfd, 2> descriptors{{
        {stdout_read ? stdout_read.get() : -1, POLLIN | POLLHUP, 0},
        {stderr_read ? stderr_read.get() : -1, POLLIN | POLLHUP, 0},
    }};
    const int poll_result = poll(descriptors.data(), descriptors.size(), 100);
    if (poll_result < 0 && errno != EINTR) {
      quietproof_internal::KillProcessGroup(child);
      result.exit_code = -1;
      break;
    }
    bool limit = false;
    (void)quietproof_internal::AppendAvailable(&stdout_read, &result.stdout_text,
                                             &limit);
    result.output_limit_exceeded |= limit;
    limit = false;
    (void)quietproof_internal::AppendAvailable(&stderr_read, &result.stderr_text,
                                             &limit);
    result.output_limit_exceeded |= limit;
    if (result.output_limit_exceeded && !child_reaped)
      quietproof_internal::KillProcessGroup(child);
    if (!child_reaped) {
      const pid_t waited = waitpid(child, &status, WNOHANG);
      if (waited == child) {
        child_reaped = true;
        child_status_available = true;
      } else if (waited < 0 && errno == ECHILD) {
        child_reaped = true;
      }
    }
    if ((result.timed_out || result.output_limit_exceeded) && child_reaped) {
      stdout_read.reset();
      stderr_read.reset();
    }
  }
  if (!child_reaped) {
    pid_t waited = -1;
    do {
      waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    child_status_available = waited == child;
  }
  if (!result.timed_out && !result.output_limit_exceeded &&
      child_status_available && WIFEXITED(status))
    result.exit_code = WEXITSTATUS(status);
  return result;
}

class BitcoinCoreCurrentTipProvider final : public QuietProofChainProvider {
 public:
  using Runner =
      std::function<QuietProofProcessResult(const std::vector<std::string>&)>;

  BitcoinCoreCurrentTipProvider(std::string executable, QuietProofNetwork network,
                                Runner runner = QuietProofRunArgv)
      : executable_(std::move(executable)), network_(network),
        runner_(std::move(runner)) {}

  QuietProofProviderKind kind() const override {
    return QuietProofProviderKind::kCurrentTip;
  }

  QuietProofChainEvidence Lookup(const QuietProofChainRequest& request) override {
    QuietProofChainEvidence evidence;
    if (!runner_ || request.has_snapshot || request.network != network_ ||
        !QuietProofNetworkValid(network_)) {
      evidence.status = QuietProofChainStatus::kInconclusive;
      evidence.detail = "provider/request mismatch";
      return evidence;
    }
    const auto tip_result = runner_(Command({"getblockchaininfo"}));
    quietproof_internal::Tip tip;
    if (tip_result.exit_code != 0 ||
        !quietproof_internal::ParseTip(tip_result.stdout_text, &tip)) {
      evidence.status = QuietProofChainStatus::kUnavailable;
      evidence.detail = "getblockchaininfo failed";
      return evidence;
    }
    if (tip.chain != QuietProofBitcoinCoreChainName(network_)) {
      evidence.status = QuietProofChainStatus::kWrongNetwork;
      evidence.detail = "Bitcoin Core network does not match statement";
      return evidence;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string txid;
    txid.reserve(64);
    for (uint8_t byte : request.txid) {
      txid.push_back(kHex[byte >> 4]);
      txid.push_back(kHex[byte & 15]);
    }
    const auto txout_result = runner_(Command(
        {"gettxout", txid, std::to_string(request.vout), "true"}));
    if (txout_result.exit_code != 0) {
      evidence.status = QuietProofChainStatus::kUnavailable;
      evidence.detail = "gettxout failed";
      return evidence;
    }
    const auto txout =
        nlohmann::json::parse(txout_result.stdout_text, nullptr, false);
    if (txout.is_discarded()) {
      evidence.status = QuietProofChainStatus::kMalformed;
      evidence.detail = "gettxout returned invalid JSON";
      return evidence;
    }
    if (txout.is_null()) {
      // gettxout cannot distinguish a spent output from a nonexistent one.
      evidence.status = QuietProofChainStatus::kInconclusive;
      evidence.detail = "outpoint is absent from the current UTXO set";
      return evidence;
    }
    if (!quietproof_internal::TxOutShapeValid(txout)) {
      evidence.status = QuietProofChainStatus::kMalformed;
      evidence.detail = "gettxout response has an unexpected shape";
      return evidence;
    }
    std::string amount_token;
    uint64_t amount_sats = 0, confirmations = 0;
    if (!quietproof_internal::TopLevelNumberToken(txout_result.stdout_text,
                                                "value", &amount_token) ||
        !quietproof_internal::ParseTxOutFields(
            txout, amount_token, tip.best_block_hash, &amount_sats,
            &confirmations, &evidence.script_pub_key)) {
      evidence.status = QuietProofChainStatus::kMalformed;
      evidence.detail = "gettxout fields are not canonical";
      return evidence;
    }

    const auto tip_after_result = runner_(Command({"getblockchaininfo"}));
    quietproof_internal::Tip tip_after;
    if (tip_after_result.exit_code != 0 ||
        !quietproof_internal::ParseTip(tip_after_result.stdout_text, &tip_after) ||
        tip_after.chain != tip.chain ||
        tip_after.best_block_hash != tip.best_block_hash ||
        tip_after.height != tip.height) {
      evidence.status = QuietProofChainStatus::kInconclusive;
      evidence.detail = "chain tip changed during lookup";
      return evidence;
    }

    evidence.network = network_;
    evidence.height = tip.height;
    evidence.confirmations = confirmations;
    evidence.amount_sats = amount_sats;
    std::vector<uint8_t> block_bytes;
    if (!quietproof_internal::DecodeHex(tip.best_block_hash, &block_bytes) ||
        block_bytes.size() != evidence.block.size()) {
      evidence.status = QuietProofChainStatus::kMalformed;
      evidence.detail = "best block hash is malformed";
      return evidence;
    }
    std::copy(block_bytes.begin(), block_bytes.end(), evidence.block.begin());
    evidence.status = QuietProofChainStatus::kUnspent;
    return evidence;
  }

 private:
  std::vector<std::string> Command(
      std::initializer_list<std::string> rpc_arguments) const {
    std::vector<std::string> arguments{executable_};
    switch (network_) {
      case QuietProofNetwork::kMainnet: break;
      case QuietProofNetwork::kTestnet3: arguments.emplace_back("-testnet"); break;
      case QuietProofNetwork::kSignet: arguments.emplace_back("-signet"); break;
      case QuietProofNetwork::kRegtest: arguments.emplace_back("-regtest"); break;
      case QuietProofNetwork::kTestnet4: arguments.emplace_back("-testnet4"); break;
    }
    arguments.insert(arguments.end(), rpc_arguments.begin(), rpc_arguments.end());
    return arguments;
  }

  std::string executable_;
  QuietProofNetwork network_;
  Runner runner_;
};

}  // namespace proofs
#endif
