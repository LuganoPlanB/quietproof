#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <streambuf>
#include <string>

#include "proof_progress.h"

namespace {
class RecordingBuffer : public std::streambuf {
 public:
  bool WaitFor(const std::string& text) {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, std::chrono::seconds(2), [&] {
      return text_.find(text) != std::string::npos;
    });
  }
  std::string Snapshot() {
    std::lock_guard lock(mutex_);
    return text_;
  }
 protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override {
    {
      std::lock_guard lock(mutex_);
      text_.append(data, count);
    }
    changed_.notify_all();
    return count;
  }
  int_type overflow(int_type character) override {
    if (traits_type::eq_int_type(character, traits_type::eof()))
      return traits_type::not_eof(character);
    const char byte = traits_type::to_char_type(character);
    xsputn(&byte, 1);
    return character;
  }
 private:
  std::mutex mutex_;
  std::condition_variable changed_;
  std::string text_;
};

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
}  // namespace

int main() {
  RecordingBuffer buffer;
  std::ostream output(&buffer);
  {
    quietproof_cli::ProofProgress progress(output, std::chrono::milliseconds(5));
    progress.SetPhase("computing commitment");
    Require(buffer.WaitFor("Proof phase: computing commitment"), "missing phase message");
    Require(buffer.WaitFor("Still working: computing commitment"), "missing heartbeat");
    progress.SetPhase("generating proof");
    Require(buffer.WaitFor("Still working: generating proof"), "heartbeat has stale phase");
  }
  const auto text = buffer.Snapshot();
  Require(text.find("s elapsed") != std::string::npos, "missing elapsed time");
  Require(text.find('%') == std::string::npos, "invented percentage");
  // Destruction must wake a sleeping reporter immediately, including unwinding.
  const auto start = std::chrono::steady_clock::now();
  try {
    quietproof_cli::ProofProgress progress(output, std::chrono::hours(1));
    throw std::runtime_error("simulated prover failure");
  } catch (const std::runtime_error&) {}
  Require(std::chrono::steady_clock::now() - start < std::chrono::seconds(2),
          "reporter delayed failure handling");
  Require(buffer.Snapshot() == text, "reporter emitted output after stopping");
  std::cout << "Proof progress tests passed\n";
}
