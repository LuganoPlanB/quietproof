// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Included inside the CLI's private namespace, after its common file/RPC helpers.

int SignatureUnavailable() {
  std::cerr << "signature_mode_disabled\n";
  return kUnsupported;
}

struct PrivateReceipt {
  std::vector<uint8_t> bytes;
  ~PrivateReceipt() { SecureErase(bytes.data(), bytes.size()); }
};

// Native inputs must be regular, bounded files; FIFOs, devices and symlinks
// cannot block or trick the private receipt path. Public requests may be shared.
bool ReadSignatureFile(const std::string& path, size_t maximum, bool private_file,
                       std::vector<uint8_t>* output) {
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return false;
  struct Close { int fd; ~Close() { close(fd); } } close_file{fd};
  struct stat status{};
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size <= 0 ||
      static_cast<uint64_t>(status.st_size) > maximum ||
      (private_file && (status.st_uid != geteuid() || (status.st_mode & 077) != 0))) return false;
  std::vector<uint8_t> bytes;
  struct Erase { std::vector<uint8_t>& bytes; ~Erase() { SecureErase(bytes.data(), bytes.size()); } } erase{bytes};
  std::array<uint8_t, 4096> buffer{};
  struct EraseBuffer { std::array<uint8_t,4096>& bytes; ~EraseBuffer() { SecureErase(bytes.data(), bytes.size()); } } erase_buffer{buffer};
  while (true) {
    const auto size = read(fd, buffer.data(), buffer.size());
    if (size < 0 && errno == EINTR) continue;
    if (size < 0 || (size > 0 && static_cast<size_t>(size) > maximum - bytes.size())) return false;
    if (size == 0) break;
    bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + size);
  }
  if (bytes.size() != static_cast<size_t>(status.st_size)) return false;
  *output = std::move(bytes);
  return true;
}

// SIGINT/TERM/HUP cannot leave a named partial file during the short atomic
// writer. Proof generation and bounded wallet RPC happen before any output is
// created, so ordinary interruption there has no file to clean up.
bool WriteSignatureFile(const std::string& path, const std::vector<uint8_t>& bytes) {
  sigset_t blocked, previous, pending;
  sigemptyset(&blocked);
  for (int signal : {SIGINT, SIGTERM, SIGHUP}) sigaddset(&blocked, signal);
  if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) return false;
  bool written = false;
  try { written = WriteNewFileAtomic(path, bytes); }
  catch (...) { (void)sigprocmask(SIG_SETMASK, &previous, nullptr); throw; }
  if (sigpending(&pending) == 0 &&
      (sigismember(&pending, SIGINT) || sigismember(&pending, SIGTERM) || sigismember(&pending, SIGHUP))) {
    if (written) (void)unlink(path.c_str());
    written = false;
  }
  (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
  if (!written) std::cerr << "could not create output file (owner-only, destination must not exist)\n";
  return written;
}

nlohmann::json SignatureRequestSummary(const proofs::QuietProofSignatureStatementV3& statement) {
  uint64_t sum = 0;
  for (const auto& claim : statement.claims) sum += claim.amount_sats; // Validated checked sum.
  return {{"audience", statement.verifier}, {"purpose", statement.purpose},
          {"network", proofs::QuietProofNetworkName(statement.network)}, {"total_sats", sum},
          {"expires_at", statement.expires_at}, {"request_created_at", statement.not_before},
          {"signing_kind", proofs::QuietProofScriptKindName(statement.signing_kind)},
          {"claims", statement.claims.size()}};
}
void ShowSignatureRequest(const proofs::QuietProofSignatureStatementV3& statement) {
  std::cerr << "Request authorisation: " << SignatureRequestSummary(statement).dump() << '\n'
            << "A private receipt permits delegated proving for this request; keep .qpa private.\n";
}
bool SignatureRequestCurrent(const proofs::QuietProofSignatureStatementV3& statement) {
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  if (now >= 0 && static_cast<uint64_t>(now) >= statement.not_before &&
      static_cast<uint64_t>(now) < statement.expires_at) return true;
  std::cerr << "signature request is expired or not yet valid\n";
  return false;
}

int SignatureOperation(const Options& options, bool export_only) {
  try {
    if (!proofs::kQuietProofSignatureModeEnabled) return SignatureUnavailable();
    std::string request_path, output_path, receipt_path, network_name;
    if (!One(options, "--request", &request_path) ||
        !One(options, export_only ? "--receipt-output" : "--output", &output_path) ||
        !One(options, "--receipt-input", &receipt_path, false) ||
        !One(options, "--network", &network_name, false) || options.count("--address")) return Usage();
    const bool imported = options.count("--receipt-input");
    if (imported) {
      if (export_only || options.count("--rpc-wallet")) return Usage();
      for (const auto& name : kRpcOptions) if (options.count(name)) return Usage();
    } else if (!options.count("--rpc-wallet")) return Usage();
    if (!CheckNewOutputPath(output_path)) return kIoError;
    std::vector<uint8_t> request;
    proofs::QuietProofSignatureStatementV3 statement;
    if (!ReadSignatureFile(request_path, proofs::kQuietProofMaxStatementBytes, false, &request) ||
        !proofs::DecodeQuietProofSignatureStatement(request, &statement)) {
      std::cerr << "signature mode requires a canonical signature-possession request\n";
      return kData;
    }
    if (options.count("--network")) {
      proofs::QuietProofNetwork network;
      if (!proofs::QuietProofParseNetwork(network_name, &network)) return Usage();
      if (network != statement.network) { std::cerr << "Network does not match the request\n"; return kData; }
    }
    ShowSignatureRequest(statement);
    if (!SignatureRequestCurrent(statement)) return kData;
    PrivateReceipt receipt;
    if (imported) {
      if (!ReadSignatureFile(receipt_path, proofs::kQuietProofSignatureMaxReceiptBytes, true, &receipt.bytes)) {
        std::cerr << "private receipt must be a bounded regular owner-only file owned by this user\n";
        return kIoError;
      }
    } else {
#ifdef QUIETPROOF_HAS_RPC
      std::string wallet;
      proofs::BitcoinCoreRpcConfig config(statement.network);
      if (!One(options, "--rpc-wallet", &wallet) || !ParseRpcOptions(options, &config)) return Usage();
      // RPC authority dies before receipt-only proving begins.
      proofs::BitcoinCoreRpc rpc(std::move(config));
      proofs::BitcoinRpcError error;
      if (!rpc.AuthorizeSignature(wallet, request, &receipt.bytes, &error)) {
        std::cerr << "signature authorisation failed: " << error.message << '\n';
        return kData;
      }
#else
      return NativeUnavailable();
#endif
    }
    proofs::QuietProofSignatureAuthorisationV1 verified;
    if (!proofs::ImportQuietProofSignatureAuthorisation(request, receipt.bytes, &verified)) {
      std::cerr << "private receipt does not authorise the expected request\n";
      return kData;
    }
    SecureErase(&verified, sizeof(verified));
    if (!SignatureRequestCurrent(statement)) return kData;
    if (export_only) {
      if (!WriteSignatureFile(output_path, receipt.bytes)) return kIoError;
      std::cout << nlohmann::json({{"result", "receipt_created"}, {"receipt", output_path}, {"private", true}}).dump() << '\n';
      return 0;
    }
    proofs::PoKSigProofV1 proof;
    proofs::PoKSigError error;
    proofs::PoKSigOptionsV1 policy;
    policy.allow_signature_possession = true;
    std::cerr << "Receipt validated. Generating signature-possession proof; this may take several minutes...\n";
    bool proved;
    {
      quietproof_cli::ProofProgress progress(std::cerr);
      proved = proofs::PoKSigProveReceipt(request, receipt.bytes, &proof, policy, &error,
          [&progress](const char* phase) { progress.SetPhase(phase); });
    }
    if (!proved) {
      std::cerr << "signature proof generation failed: " << proofs::PoKSigErrorName(error) << '\n';
      return 2;
    }
    if (!SignatureRequestCurrent(statement)) return kData;
    if (!WriteSignatureFile(output_path, proof.bytes)) return kIoError;
    std::cout << nlohmann::json({{"result", "proof_created"}, {"proof", output_path},
                                {"proof_mode", "signature-possession"}, {"proof_bytes", proof.bytes.size()}}).dump() << '\n';
    return 0;
  } catch (...) {
    std::cerr << "signature operation failed; private diagnostics suppressed\n";
    return kSoftware;
  }
}

int SignatureAuthorize(int argc, char** argv) {
  auto allowed = kRpcOptions;
  allowed.insert({"--proof-mode", "--request", "--receipt-output", "--rpc-wallet", "--network"});
  Options options;
  std::string mode;
  if (!ParseOptions(argc, argv, 2, allowed, &options) ||
      !One(options, "--proof-mode", &mode) || mode != "signature-possession") return Usage();
  return SignatureOperation(options, true);
}


// Offline request material and external signature import share the established
// protected file IO. Signature bytes never appear in argv or diagnostics.
int SignatureExternal(int argc, char** argv, bool importing) {
  try {
    const std::set<std::string> allowed = importing ? std::set<std::string>{
        "--proof-mode", "--request", "--signature-input", "--signature-format",
        "--receipt-output", "--network", "--address"} : std::set<std::string>{
        "--proof-mode", "--request", "--output", "--network", "--address"};
    Options options;
    std::string mode, request_path, output_path, network_name, address, input_path, format;
    if (!ParseOptions(argc, argv, 2, allowed, &options) ||
        !One(options, "--proof-mode", &mode) || mode != "signature-possession" ||
        !One(options, "--request", &request_path) ||
        !One(options, importing ? "--receipt-output" : "--output", &output_path) ||
        !One(options, "--network", &network_name, false) || !One(options, "--address", &address, false) ||
        (importing && (!One(options, "--signature-input", &input_path) ||
                       !One(options, "--signature-format", &format)))) return Usage();
    if (!proofs::kQuietProofSignatureModeEnabled) return SignatureUnavailable();
    if (!CheckNewOutputPath(output_path)) return kIoError;
    std::vector<uint8_t> request;
    proofs::QuietProofSignatureStatementV3 statement;
    proofs::QuietProofSignatureInputsV1 inputs;
    if (!ReadSignatureFile(request_path, proofs::kQuietProofMaxStatementBytes, false, &request) ||
        !proofs::DecodeQuietProofSignatureStatement(request, &statement) ||
        !proofs::DeriveQuietProofSignatureInputs(request, &inputs)) {
      std::cerr << "canonical signature-possession request required\n"; return kData;
    }
    if (options.count("--network")) {
      proofs::QuietProofNetwork network;
      if (!proofs::QuietProofParseNetwork(network_name, &network)) return Usage();
      if (network != statement.network) { std::cerr << "Network does not match the request\n"; return kData; }
    }
    const auto expected_address = proofs::QuietProofSignatureAddress(statement);
    if (options.count("--address") && address != expected_address) {
      std::cerr << "Address does not match the request\n"; return kData;
    }
    ShowSignatureRequest(statement);
    if (!SignatureRequestCurrent(statement)) return kData;
    if (!importing) {
      const auto& message = inputs.profile.application_message;
      if (!WriteSignatureFile(output_path, {message.begin(), message.end()})) return kIoError;
      auto summary = SignatureRequestSummary(statement);
      summary["result"] = "signing_material_created";
      summary["address"] = expected_address;
      summary["statement_digest"] = ArrayHex(inputs.profile.statement_digest);
      summary["message"] = std::string(message.begin(), message.end());
      summary["message_bytes"] = message.size();
      summary["message_file"] = output_path;
      std::cout << summary.dump() << '\n';
      return 0;
    }
    PrivateReceipt encoded, receipt;
    if (!ReadSignatureFile(input_path, 16384, true, &encoded.bytes)) {
      std::cerr << "signature input must be a bounded regular owner-only file owned by this user\n"; return kIoError;
    }
    std::string signature(encoded.bytes.begin(), encoded.bytes.end());
    struct EraseString { std::string& value; ~EraseString() { SecureErase(value.data(), value.size()); } } erase{signature};
    if (format == "sparrow-json") {
      // Treat metadata as assertions, never authority. Native verification below
      // binds the signature to the request even if metadata has been forged.
      const auto wrapper = nlohmann::json::parse(signature);
      std::array<uint8_t, 32> message_hash{};
      proofs::SHA256 hash;
      hash.Update(inputs.profile.application_message.data(), inputs.profile.application_message.size());
      hash.DigestData(message_hash.data());
      if (wrapper.at("network").get<std::string>() != proofs::QuietProofNetworkName(statement.network) ||
          wrapper.at("address").get<std::string>() != expected_address ||
          wrapper.at("scriptKind").get<std::string>() != proofs::QuietProofScriptKindName(statement.signing_kind) ||
          wrapper.at("messageSha256").get<std::string>() != ArrayHex(message_hash)) {
        std::cerr << "signature metadata does not match the request\n"; return kData;
      }
      format = wrapper.at("format").get<std::string>();
      SecureErase(signature.data(), signature.size());
      signature = wrapper.at("signature").get<std::string>();
    }
    proofs::QuietProofBip322Format selected;
    if (format == "bip322-simple") selected = proofs::QuietProofBip322Format::kSimple;
    else if (format == "bip322-full") selected = proofs::QuietProofBip322Format::kFull;
    else { std::cerr << "unsupported signature scheme; BIP322 ECDSA required\n"; return kUnsupported; }
    proofs::QuietProofSignatureAuthorisationError error;
    if (!proofs::ImportQuietProofBip322Signature(request, selected, signature, &receipt.bytes, &error)) {
      std::cerr << "external signature rejected: " << proofs::QuietProofSignatureAuthorisationErrorName(error) << '\n';
      return error == proofs::QuietProofSignatureAuthorisationError::kUnsupported ? kUnsupported : kData;
    }
    if (!SignatureRequestCurrent(statement)) return kData;
    if (!WriteSignatureFile(output_path, receipt.bytes)) return kIoError;
    std::cout << nlohmann::json({{"result", "receipt_created"}, {"receipt", output_path}, {"private", true}}).dump() << '\n';
    return 0;
  } catch (...) {
    std::cerr << "external signature operation failed; private diagnostics suppressed\n"; return kData;
  }
}
