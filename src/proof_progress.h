#ifndef QUIETPROOF_CLI_PROOF_PROGRESS_H_
#define QUIETPROOF_CLI_PROOF_PROGRESS_H_

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <ostream>
#include <string>
#include <thread>

namespace quietproof_cli {

// Reports elapsed time, not a percentage or evidence of forward progress.
// The output stream must outlive this object. No key material enters it.
class ProofProgress {
 public:
  explicit ProofProgress(std::ostream& output,
                         std::chrono::milliseconds interval = std::chrono::seconds(10))
      : output_(output), started_(std::chrono::steady_clock::now()),
        worker_([this, interval] {
          std::unique_lock lock(mutex_);
          while (!changed_.wait_for(lock, interval, [this] { return stopped_; })) {
            Report("Still working: ");
          }
        }) {}

  ~ProofProgress() {
    {
      std::lock_guard lock(mutex_);
      stopped_ = true;
    }
    changed_.notify_one();
    worker_.join();
  }

  ProofProgress(const ProofProgress&) = delete;
  ProofProgress& operator=(const ProofProgress&) = delete;

  void SetPhase(const char* phase) {
    std::lock_guard lock(mutex_);
    phase_ = phase;
    Report("Proof phase: ");
  }

 private:
  void Report(const char* prefix) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - started_).count();
    output_ << prefix << phase_ << " (" << elapsed << " s elapsed).\n" << std::flush;
  }

  std::ostream& output_;
  const std::chrono::steady_clock::time_point started_;
  std::mutex mutex_;
  std::condition_variable changed_;
  bool stopped_ = false;
  std::string phase_ = "preparing proof";
  std::thread worker_;
};

}  // namespace quietproof_cli

#endif
