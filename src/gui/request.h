#pragma once

#include "quietproof/statement.h"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace quietproof::gui {
// The reviewed wire bytes and decoded value travel together, without mutation.
struct LoadedRequest {
  const std::filesystem::path path;
  const std::vector<uint8_t> bytes;
  const proofs::QuietProofStatementV1 statement;
};
enum class RequestError { None, Unreadable, TooLarge, ProofFile, Unsupported, Malformed };
struct RequestState {
  std::shared_ptr<const LoadedRequest> loaded;
  RequestError error = RequestError::None;
  uint64_t revision = 0;
  // A canceled chooser is not a replacement. Every attempted load invalidates
  // the old request before any I/O, including failed replacements.
  void Open(const std::optional<std::filesystem::path>& path);
  const char* Message() const;
};

struct FileEntry {
  std::filesystem::path path;
  bool directory = false;
};
struct RequestChooser {
  bool open = false;
  std::filesystem::path directory;
  std::vector<FileEntry> entries;
  std::string error;
  void Browse(const std::filesystem::path& path);
  void Cancel() { open = false; }
};
}  // namespace quietproof::gui
