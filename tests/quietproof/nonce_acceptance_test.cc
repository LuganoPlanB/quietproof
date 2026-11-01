// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Separate-process test interface; fixed public window and redacted diagnostics.
#include <fstream>
#include <iostream>
#include <stdexcept>
#include "quietproof/nonce_store.h"

namespace {
using namespace proofs;
const char* Name(QuietProofFinalAcceptanceStatus status) {
  switch (status) {
    case QuietProofFinalAcceptanceStatus::kAccepted: return "accepted";
    case QuietProofFinalAcceptanceStatus::kReplay: return "replay";
    case QuietProofFinalAcceptanceStatus::kNotYetValid: return "not_yet_valid";
    case QuietProofFinalAcceptanceStatus::kExpired: return "expired";
    case QuietProofFinalAcceptanceStatus::kClockUnavailable: return "clock_unavailable";
    case QuietProofFinalAcceptanceStatus::kInvalidRequest: return "invalid_request";
    default: return "store_failure";
  }
}
}
int main(int argc, char** argv) {
  try {
    if (argc != 5 && argc != 6) throw 1;
    const std::string mode = argv[1], path = argv[2], time_path = argv[3];
    QuietProofFinalAcceptanceRequest request;
    request.nonce[0] = static_cast<uint8_t>(std::stoul(argv[4]));
    request.not_before = 100; request.expires_at = 200;
    unsigned clock_calls = 0;
    const auto clock = [&](uint64_t* output) {
      ++clock_calls;
      // A distinct open file description must be unable to acquire the lock:
      // this proves clock execution is inside the operation's serialization.
      const int probe = open(path.c_str(), O_RDWR | O_CLOEXEC);
      if (probe < 0) throw 1;
      const int result = flock(probe, LOCK_EX | LOCK_NB);
      const int failure = errno;
      if (result == 0) (void)flock(probe, LOCK_UN);
      close(probe);
      if (result == 0 || (failure != EWOULDBLOCK && failure != EAGAIN)) throw 1;
      const std::string marker = time_path + ".clock";
      const int fd = open(marker.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
      if (fd < 0 || write(fd, "C", 1) != 1) { if (fd >= 0) close(fd); throw 1; }
      close(fd);
      std::ifstream input(time_path);
      std::string value; input >> value;
      if (!input || value == "fail") return false;
      if (value == "throw") throw std::runtime_error("private-clock-error-must-not-appear");
      *output = std::stoull(value);
      return true;
    };
    std::cout << "ready\n" << std::flush;
    if (argc == 6) {
      char gate;
      ssize_t read_count;
      do { read_count = read(std::stoi(argv[5]), &gate, 1); } while (read_count < 0 && errno == EINTR);
      if (read_count != 1) throw 1;
    }
    QuietProofFinalAcceptance result;
    if (mode == "legacy") result.status = QuietProofConsumeNonceFile(path, request.nonce) ?
        QuietProofFinalAcceptanceStatus::kAccepted : QuietProofFinalAcceptanceStatus::kReplay;
    else if (mode == "accept") {
      QuietProofNonceFileAcceptanceStore store(path);
      result = store.Accept(request, clock);
    } else throw 1;
    std::cout << Name(result.status) << ' ' << result.accepted_at << ' ' << clock_calls << '\n';
    return 0;
  } catch (...) { std::cerr << "nonce acceptance driver failed\n"; return 1; }
}
