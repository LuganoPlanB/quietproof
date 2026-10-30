#include "proof_output.h"
#include "pokc/verifier.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace quietproof::gui {
ProofValidation ProofValidation::Run(std::shared_ptr<const LoadedRequest> request,
    const proofs::QuietProofEnvelopeV1& envelope, const std::function<bool()>& canceled,
    const ProofVerifier& test_verifier) {
  if (canceled()) return {{},"Proof validation canceled"};
  std::vector<uint8_t> reviewed, actual;
  if (!request || !proofs::EncodeQuietProofStatement(request->statement,&reviewed) ||
      reviewed != request->bytes || !proofs::EncodeQuietProofStatement(envelope.statement,&actual) || actual != reviewed)
    return {{},"Generated proof does not match the exact reviewed request"};
  if (!proofs::QuietProofEnvelopeTimeValid(envelope) ||
      !(test_verifier ? test_verifier(envelope) : proofs::PoKCVerifyProof(envelope)))
    return {{},"Generated proof failed local cryptographic verification"};
  if (canceled()) return {{},"Proof validation canceled"};
  std::vector<uint8_t> bytes;
  if (!proofs::EncodeQuietProofEnvelope(envelope,&bytes)) return {{},"Verified proof could not be encoded"};
  if (canceled()) return {{},"Proof validation canceled"};
  return {std::shared_ptr<const VerifiedProof>(new VerifiedProof(std::move(request),std::move(bytes),envelope.proof_created_at)),{}};
}
namespace {
struct Descriptor {
  int value = -1;
  ~Descriptor() { if (value >= 0) close(value); }
};
OutputIdentity Identity(const struct stat& s, const std::filesystem::path& destination) {
  return {static_cast<uint64_t>(s.st_dev),static_cast<uint64_t>(s.st_ino),static_cast<uint64_t>(s.st_size),
    s.st_mtim.tv_sec,s.st_mtim.tv_nsec,s.st_ctim.tv_sec,s.st_ctim.tv_nsec,
    std::filesystem::absolute(destination).lexically_normal()};
}
}
SaveResult RunSave(const SaveJob& job, const std::function<bool()>& canceled, const SaveHooks& hooks) {
  SaveResult result; result.revision = job.revision; result.attempt = job.attempt;
  result.destination = job.destination;
  Descriptor directory, output;
  std::string temporary;
  auto clean = [&] {
    if (!temporary.empty()) {
      if (unlinkat(directory.value,temporary.c_str(),0) != 0 && errno != ENOENT) result.cleanup_failed = true;
      temporary.clear();
    }
  };
  struct Cleanup { decltype(clean)& run; ~Cleanup() { run(); } } cleanup{clean};
  auto cancel = [&] {
    if (!canceled()) return false;
    result.status = SaveStatus::Canceled; result.message = "Save canceled before publication. Verified proof remains available";
    return true;
  };
  auto fail = [&](const char* message) { result.status = SaveStatus::Failed; result.message = message; };
  auto run = [&] {
  try {
    if (cancel()) return;
    const auto filename = job.destination.filename().string();
    if (!job.proof || filename.empty() || filename == "." || filename == "..") {
      fail("Choose a destination filename for the verified proof"); return;
    }
    const auto parent = job.destination.has_parent_path() ? job.destination.parent_path() : std::filesystem::path(".");
    directory.value = open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (directory.value < 0) { fail("Destination folder is unavailable or not accessible. Proof retained for retry"); return; }
    struct stat existing{};
    const bool exists = fstatat(directory.value,filename.c_str(),&existing,AT_SYMLINK_NOFOLLOW) == 0;
    if (!exists && errno != ENOENT) { fail("Cannot inspect destination. Proof retained for retry"); return; }
    if (exists && !S_ISREG(existing.st_mode)) { fail("Destination must be a regular file; links and special files are not replaced"); return; }
    if (exists && !job.replace) {
      result.status = SaveStatus::NeedsOverwrite; result.existing = Identity(existing,job.destination);
      result.message = "Destination already exists. Explicitly confirm replacement of this file"; return;
    }
    if ((job.replace && !exists) || (exists && job.replace && *job.replace != Identity(existing,job.destination))) {
      result.status = SaveStatus::DestinationChanged; result.message = "Destination changed since confirmation. Review it and try again"; return;
    }
    std::array<uint8_t,16> random{};
    size_t offset = 0;
    while (offset < random.size()) {
      const auto n = getrandom(random.data()+offset,random.size()-offset,0);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { fail("Cannot create a safe temporary output. Proof retained for retry"); return; }
      offset += static_cast<size_t>(n);
    }
    constexpr char hex[] = "0123456789abcdef";
    temporary = ".quietproof-"+std::to_string(getpid())+"-";
    for (const auto byte : random) { temporary += hex[byte>>4]; temporary += hex[byte&15]; }
    output.value = openat(directory.value,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (output.value < 0) { temporary.clear(); fail("Cannot create output in destination folder. Check permissions or free space; proof retained"); return; }
    if (hooks.observe) hooks.observe(SavePoint::TemporaryCreated);
    const auto& bytes = job.proof->Bytes(); offset = 0;
    while (offset < bytes.size()) {
      if (cancel()) return;
      const auto chunk = std::span<const uint8_t>(bytes).subspan(offset,std::min<size_t>(65536,bytes.size()-offset));
      const auto n = hooks.write ? hooks.write(output.value,chunk) : write(output.value,chunk.data(),chunk.size());
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0 || static_cast<size_t>(n)>chunk.size()) { fail("Proof write failed. Check free space or file limits; previous output preserved, proof retained"); return; }
      offset += static_cast<size_t>(n);
    }
    if (hooks.observe) hooks.observe(SavePoint::Written);
    if ((hooks.sync ? hooks.sync(output.value) : fsync(output.value)) != 0) { fail("Could not synchronize proof bytes. Previous output preserved; proof retained"); return; }
    const int closed = close(output.value); output.value = -1;
    if (closed != 0) { fail("Could not close proof output. Previous output preserved; proof retained"); return; }
    if (hooks.observe) hooks.observe(SavePoint::BeforeCommit);
    if (cancel()) return;
    // Recheck the confirmed identity immediately before publication. POSIX has
    // no compare-and-replace primitive against unrelated external writers.
    if (job.replace) {
      struct stat current{};
      if (fstatat(directory.value,filename.c_str(),&current,AT_SYMLINK_NOFOLLOW) != 0 ||
          !S_ISREG(current.st_mode) || Identity(current,job.destination) != *job.replace) {
        result.status = SaveStatus::DestinationChanged; result.message = "Destination changed during saving. Previous output preserved; review and retry"; return;
      }
      if (renameat(directory.value,temporary.c_str(),directory.value,filename.c_str()) != 0) { fail("Could not publish replacement. Previous output preserved; proof retained"); return; }
      temporary.clear();
    } else if (linkat(directory.value,temporary.c_str(),directory.value,filename.c_str(),0) != 0) {
      result.status = SaveStatus::DestinationChanged; result.message = "Destination appeared or could not be published. No existing file replaced; review and retry"; return;
    }
    // Publication is the cancellation boundary. A late cancel never deletes a
    // complete published proof or claims that an existing file was preserved.
    result.committed = true; result.status = SaveStatus::Saved;
    clean();
    if (hooks.observe) hooks.observe(SavePoint::Committed);
    result.durability_warning = (hooks.sync_directory ? hooks.sync_directory(directory.value) : fsync(directory.value)) != 0;
    result.message = result.durability_warning ? "Complete proof saved, but folder synchronization was not confirmed; check storage durability" : "Verified proof saved. Current chain state has not been checked";
  } catch (...) {
    if (result.committed) { result.status = SaveStatus::Saved; result.durability_warning = true; result.message = "Complete proof published; final storage confirmation failed"; }
    else fail("Save failed. Previous output preserved; verified proof retained for retry");
  }
  };
  run();
  clean();
  return result;
}
}  // namespace quietproof::gui
