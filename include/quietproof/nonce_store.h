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
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_NONCE_STORE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_NONCE_STORE_H_

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <utility>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "quietproof/acceptance.h"

namespace proofs {

constexpr size_t kQuietProofMaxNonceStoreBytes = size_t{16} * 1024 * 1024;

inline bool QuietProofWriteAll(int descriptor, const uint8_t* bytes, size_t size) {
  while (size != 0) {
    const ssize_t written = write(descriptor, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    bytes += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

inline std::string QuietProofNonceHex(const std::array<uint8_t, 32>& nonce) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(nonce.size() * 2);
  for (uint8_t byte : nonce) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 15]);
  }
  return output;
}

inline bool QuietProofFsyncParentDirectory(const std::string& path) {
  const size_t separator = path.find_last_of('/');
  const std::string directory = separator == std::string::npos
                                    ? "."
                                    : separator == 0 ? "/" : path.substr(0, separator);
  const int descriptor =
      open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (descriptor < 0) return false;
  const bool result = fsync(descriptor) == 0;
  (void)close(descriptor);
  return result;
}

// Atomically reject an existing nonce or append a new one. The store must be a
// regular file owned by the effective user with no group/other permissions.
inline bool QuietProofConsumeNonceFile(const std::string& path,
                                     const std::array<uint8_t, 32>& nonce) {
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC |
                                                O_NOFOLLOW, 0600);
  if (descriptor < 0) return false;
  struct stat metadata {};
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_uid != geteuid() || (metadata.st_mode & 077) != 0 ||
      flock(descriptor, LOCK_EX) != 0) {
    (void)close(descriptor);
    return false;
  }

  bool result = false;
  const std::string needle = QuietProofNonceHex(nonce);
  std::string contents;
  std::array<char, 4096> buffer{};
  if (lseek(descriptor, 0, SEEK_SET) >= 0) {
    while (contents.size() <= kQuietProofMaxNonceStoreBytes) {
      const ssize_t count = read(descriptor, buffer.data(), buffer.size());
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) break;
      if (count == 0) {
        bool seen = false;
        size_t begin = 0;
        while (begin < contents.size()) {
          const size_t end = contents.find('\n', begin);
          if (contents.substr(begin, end - begin) == needle) seen = true;
          if (end == std::string::npos) break;
          begin = end + 1;
        }
        if (!seen && lseek(descriptor, 0, SEEK_END) >= 0) {
          const std::string record = needle + "\n";
          result = QuietProofWriteAll(
                       descriptor,
                       reinterpret_cast<const uint8_t*>(record.data()),
                       record.size()) &&
                   fsync(descriptor) == 0 &&
                   QuietProofFsyncParentDirectory(path);
        }
        break;
      }
      if (static_cast<size_t>(count) >
          kQuietProofMaxNonceStoreBytes -
              std::min(contents.size(), kQuietProofMaxNonceStoreBytes)) break;
      contents.append(buffer.data(), static_cast<size_t>(count));
    }
  }
  (void)flock(descriptor, LOCK_UN);
  (void)close(descriptor);
  return result;
}

// Signature acceptance uses the SAME bare nonce records as the old scalar API.
// The old API above deliberately retains its existing behavior. A failed write
// or fsync is never acceptance; a nonce may remain recorded after such a failure.
inline QuietProofFinalAcceptance QuietProofAcceptNonceFile(
    const std::string& path, const QuietProofFinalAcceptanceRequest& request,
    const QuietProofClock& clock = QuietProofSystemClock) {
  using Status = QuietProofFinalAcceptanceStatus;
  if (request.not_before >= request.expires_at ||
      std::all_of(request.nonce.begin(), request.nonce.end(), [](uint8_t x) { return x == 0; }))
    return {Status::kInvalidRequest};
  if (path.empty() || path.find('\0') != std::string::npos) return {Status::kStoreFailure};
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
  if (descriptor < 0) return {Status::kStoreFailure};
  struct Guard {
    int fd;
    bool locked = false;
    ~Guard() { if (locked) (void)flock(fd, LOCK_UN); (void)close(fd); }
  } guard{descriptor};
  const auto metadata_valid = [&] {
    struct stat metadata{};
    return fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        metadata.st_uid == geteuid() && (metadata.st_mode & 077) == 0 && metadata.st_size >= 0 &&
        static_cast<uint64_t>(metadata.st_size) <= kQuietProofMaxNonceStoreBytes;
  };
  if (!metadata_valid()) return {Status::kStoreFailure};
  while (flock(descriptor, LOCK_EX) != 0) {
    if (errno != EINTR) return {Status::kStoreFailure};
  }
  guard.locked = true;
  // Permissions, type and size may have changed while waiting for the lock.
  if (!metadata_valid() || lseek(descriptor, 0, SEEK_SET) < 0) return {Status::kStoreFailure};
  std::string contents;
  std::array<char, 4096> buffer{};
  while (true) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return {Status::kStoreFailure};
    if (!count) break;
    if (static_cast<size_t>(count) > kQuietProofMaxNonceStoreBytes - contents.size())
      return {Status::kStoreFailure};
    contents.append(buffer.data(), static_cast<size_t>(count));
  }
  // Truncated/noncanonical records cannot be silently joined to a new record,
  // which could erase replay protection. No record is evicted or rewritten.
  if (contents.size() % 65) return {Status::kStoreFailure};
  const auto needle = QuietProofNonceHex(request.nonce);
  bool seen = false;
  for (size_t offset = 0; offset < contents.size(); offset += 65) {
    if (contents[offset + 64] != '\n') return {Status::kStoreFailure};
    for (size_t i = 0; i < 64; ++i) {
      const char c = contents[offset + i];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return {Status::kStoreFailure};
    }
    seen |= contents.compare(offset, 64, needle) == 0;
  }
  uint64_t now = 0;
  // This is the acceptance decision time, AFTER lock waiting and store reads.
  if (!QuietProofReadClock(clock, &now)) return {Status::kClockUnavailable};
  if (now < request.not_before) return {Status::kNotYetValid};
  if (now >= request.expires_at) return {Status::kExpired};
  if (seen) return {Status::kReplay};
  if (contents.size() > kQuietProofMaxNonceStoreBytes - 65 || lseek(descriptor, 0, SEEK_END) < 0)
    return {Status::kStoreFailure};
  const std::string record = needle + "\n";
  if (!QuietProofWriteAll(descriptor, reinterpret_cast<const uint8_t*>(record.data()), record.size()) ||
      fsync(descriptor) != 0 || !QuietProofFsyncParentDirectory(path)) return {Status::kStoreFailure};
  return {Status::kAccepted, now};
}

class QuietProofNonceFileAcceptanceStore final : public QuietProofFinalAcceptanceStore {
 public:
  explicit QuietProofNonceFileAcceptanceStore(std::string path) : path_(std::move(path)) {}
  QuietProofFinalAcceptance Accept(const QuietProofFinalAcceptanceRequest& request,
                                   const QuietProofClock& clock) override {
    return QuietProofAcceptNonceFile(path_, request, clock);
  }
 private:
  std::string path_;
};

}  // namespace proofs
#endif
