#include "request.h"

#include <algorithm>
#include <array>
#include <fstream>

namespace quietproof::gui {
void RequestState::Open(const std::optional<std::filesystem::path>& path) {
  if (!path) return;
  loaded.reset();
  ++revision;
  error = RequestError::Unreadable;
  std::error_code status_error;
  if (!std::filesystem::is_regular_file(*path, status_error) || status_error) return;
  std::ifstream input(*path, std::ios::binary);
  if (!input) return;
  // Read only the request ceiling plus one byte, even for a growing file.
  std::array<char, proofs::kQuietProofMaxStatementBytes + 1> buffer{};
  input.read(buffer.data(), buffer.size());
  const auto count = static_cast<size_t>(input.gcount());
  if (input.bad() || (!input.eof() && input.fail())) return;
  if (count >= 4 && std::equal(buffer.begin(), buffer.begin() + 4, "QPE1")) {
    error = RequestError::ProofFile;
    return;
  }
  if (count > proofs::kQuietProofMaxStatementBytes) {
    error = RequestError::TooLarge;
    return;
  }
  std::vector<uint8_t> bytes(buffer.begin(), buffer.begin() + count);
  proofs::QuietProofStatementV1 statement;
  proofs::QuietProofDecodeError decode_error;
  if (!proofs::DecodeQuietProofStatement(bytes, &statement, &decode_error)) {
    error = decode_error == proofs::QuietProofDecodeError::kUnsupported ?
      RequestError::Unsupported : RequestError::Malformed;
    return;
  }
  loaded = std::make_shared<const LoadedRequest>(LoadedRequest{*path, std::move(bytes), std::move(statement)});
  error = RequestError::None;
}

const char* RequestState::Message() const {
  switch (error) {
    case RequestError::None: return loaded ? "Request loaded. Wallet access is unavailable." : "No request loaded. Choose a request file.";
    case RequestError::Unreadable: return "Cannot read this file. Check the path and read permissions, then try again.";
    case RequestError::TooLarge: return "File exceeds the 4096-byte request limit. Ask the verifier for a request file.";
    case RequestError::ProofFile: return "This is a proof file, not a request. Open the original request supplied by your verifier.";
    case RequestError::Unsupported: return "Unsupported request version, network or script kind. Ask the verifier for a supported v1 or v2 request.";
    case RequestError::Malformed: return "Invalid or incomplete request. Obtain the complete original request and try again.";
  }
  return "Cannot load request.";
}

void RequestChooser::Browse(const std::filesystem::path& path) {
  open = true;
  entries.clear();
  error.clear();
  std::error_code status_error;
  auto next = path.empty() ? std::filesystem::current_path(status_error) : path;
  if (!std::filesystem::is_directory(next, status_error)) next = next.parent_path();
  if (next.empty()) next = ".";
  directory = next;
  std::filesystem::directory_iterator iterator(directory, status_error), end;
  if (status_error) { error = "Cannot list this folder. Enter a readable folder or file path."; return; }
  for (; iterator != end; iterator.increment(status_error)) {
    if (status_error) break;
    const auto& item = *iterator;
    std::error_code entry_error;
    const bool is_directory = item.is_directory(entry_error);
    if (entry_error || (!is_directory && !item.is_regular_file(entry_error))) continue;
    if (entries.size() == 256) {
      error = "Showing the first 256 entries. Enter an exact path to choose another file.";
      break;
    }
    entries.push_back({item.path(), is_directory});
  }
  if (status_error) error = "Folder listing stopped. Enter an exact file path or choose another folder.";
  std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
    if (left.directory != right.directory) return left.directory > right.directory;
    return left.path.filename() < right.path.filename();
  });
}
}  // namespace quietproof::gui
