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
  // Separate relation; statement is populated only for legacy PoKC.
  const std::optional<proofs::QuietProofSignatureStatementV4> signature = {};
  proofs::QuietProofNetwork Network() const { return signature ? signature->network : statement.network; }
  const std::string& Verifier() const { return signature ? signature->verifier : statement.verifier; }
  const auto& Claims() const { return signature ? signature->claims : statement.claims; }
  uint8_t Version() const { return signature ? signature->statement_version : statement.statement_version; }
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
