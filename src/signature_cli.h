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

nlohmann::json SignatureRequestSummary(const proofs::QuietProofSignatureStatementV4& statement) {
  uint64_t sum = 0;
  for (const auto& claim : statement.claims) sum += claim.amount_sats; // Validated checked sum.
  return {{"audience", statement.verifier}, {"purpose", statement.purpose},
          {"network", proofs::QuietProofNetworkName(statement.network)}, {"total_sats", sum},
          {"expires_at", statement.expires_at}, {"request_created_at", statement.not_before},
          {"signing_kind", proofs::QuietProofScriptKindName(statement.signing_kind)},
          {"request_version", statement.statement_version},
          {"signing_profile", proofs::QuietProofSigningProfileName(statement.signing_profile)},
          {"profile_version", statement.profile_version},
          {"signing_profile_label", proofs::QuietProofSigningProfileDescriptorFor(statement.signing_profile)->label},
          {"signing_address", proofs::QuietProofSignatureAddress(statement)},
          {"signing_instructions", proofs::QuietProofSigningInstructions(statement.signing_profile, statement.signing_kind)},
          {"approved_proof_procedure", "ECDSA/HASH160 signature custody (one proof)"},
          {"approved_circuit_digest", ArrayHex(proofs::PoKSigExpectedCircuitDigest())},
          {"claims", statement.claims.size()}};
}
bool DecodeSignatureRequest(const std::vector<uint8_t>& request,
                            proofs::QuietProofSignatureStatementV4* statement,
                            proofs::QuietProofDecodeError* error) {
  if (proofs::DecodeQuietProofSignatureStatement(request, statement, error)) return true;
  if (request.size() >= 5 && std::memcmp(request.data(), "QPS1", 4) == 0 &&
      (request[4] == 1 || request[4] == 2)) {
    *error = proofs::QuietProofDecodeError::kMalformed;
    std::cerr << "PoKC request requires explicit --proof-mode key-knowledge; PoSC requires a v4 request\n";
    return false;
  }
  if (request.size() >= 5 && std::memcmp(request.data(), "QPS1", 4) == 0 && request[4] == 3)
    std::cerr << "superseded PoSC v3 request; reissue a v4 request and obtain fresh signatures/receipts/proofs\n";
  else std::cerr << (*error == proofs::QuietProofDecodeError::kUnsupported ?
      "unsupported signature request profile/version\n" : "canonical v4 signature-possession request required\n");
  return false;
}
void ShowSignatureRequest(const proofs::QuietProofSignatureStatementV4& statement) {
  std::cerr << "Request authorisation: " << SignatureRequestSummary(statement).dump() << '\n'
            << "A private receipt permits delegated proving for this request; keep .qpa private.\n";
}
bool SignatureRequestCurrent(const proofs::QuietProofSignatureStatementV4& statement) {
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
    proofs::QuietProofSignatureStatementV4 statement;
    proofs::QuietProofDecodeError decode_error;
    if (!ReadSignatureFile(request_path, proofs::kQuietProofMaxStatementBytes, false, &request)) return kData;
    if (!DecodeSignatureRequest(request, &statement, &decode_error))
      return decode_error == proofs::QuietProofDecodeError::kUnsupported ? kUnsupported : kData;
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
    proofs::QuietProofSignatureAuthorisationError authorization_error;
    if (!proofs::ImportQuietProofSignatureAuthorisation(request, receipt.bytes, &verified, &authorization_error)) {
      if (authorization_error == proofs::QuietProofSignatureAuthorisationError::kUnsupported) {
        std::cerr << "unsupported or superseded receipt; obtain a fresh v4 request-bound signature/receipt\n";
        return kUnsupported;
      }
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
    auto summary = SignatureRequestSummary(statement);
    summary["result"] = "proof_created"; summary["proof"] = output_path;
    summary["proof_mode"] = "signature-possession"; summary["proof_bytes"] = proof.bytes.size();
    std::cout << summary.dump() << '\n';
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
  std::string mode = "signature-possession";
  if (!ParseOptions(argc, argv, 2, allowed, &options) ||
      !One(options, "--proof-mode", &mode, false) || mode != "signature-possession") return Usage();
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
    std::string mode = "signature-possession", request_path, output_path, network_name, address, input_path, format;
    if (!ParseOptions(argc, argv, 2, allowed, &options) ||
        !One(options, "--proof-mode", &mode, false) || mode != "signature-possession" ||
        !One(options, "--request", &request_path) ||
        !One(options, importing ? "--receipt-output" : "--output", &output_path) ||
        !One(options, "--network", &network_name, false) || !One(options, "--address", &address, false) ||
        (importing && (!One(options, "--signature-input", &input_path) ||
                       !One(options, "--signature-format", &format)))) return Usage();
    if (!proofs::kQuietProofSignatureModeEnabled) return SignatureUnavailable();
    if (!CheckNewOutputPath(output_path)) return kIoError;
    std::vector<uint8_t> request;
    proofs::QuietProofSignatureStatementV4 statement;
    proofs::QuietProofSignatureInputsV1 inputs;
    proofs::QuietProofDecodeError decode_error;
    if (!ReadSignatureFile(request_path, proofs::kQuietProofMaxStatementBytes, false, &request)) return kData;
    if (!DecodeSignatureRequest(request, &statement, &decode_error))
      return decode_error == proofs::QuietProofDecodeError::kUnsupported ? kUnsupported : kData;
    if (!proofs::DeriveQuietProofSignatureInputs(request, &inputs)) return kUnsupported;
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
          (wrapper.contains("signingProfile") && wrapper.at("signingProfile").get<std::string>() !=
              proofs::QuietProofSigningProfileName(statement.signing_profile)) ||
          (wrapper.contains("profileVersion") &&
              (!wrapper.at("profileVersion").is_number_unsigned() ||
               wrapper.at("profileVersion").get<uint64_t>() != statement.profile_version)) ||
          wrapper.at("messageSha256").get<std::string>() != ArrayHex(message_hash)) {
        std::cerr << "signature metadata does not match the request\n"; return kData;
      }
      format = wrapper.at("format").get<std::string>();
      if ((format == "standard" || format == "electrum" || format == "bip137") &&
          statement.signing_profile == proofs::QuietProofSigningProfile::kBitcoinMessageEcdsaV1)
        format = "bitcoin-message";  // Known compact transports, still checked by header/profile below.
      SecureErase(signature.data(), signature.size());
      signature = wrapper.at("signature").get<std::string>();
    }
    proofs::QuietProofSignatureAuthorisationError error;
    bool imported;
    if (format == "bitcoin-message") {
      imported = proofs::ImportQuietProofBitcoinMessageSignature(request, signature, &receipt.bytes, &error);
    } else if (format == "bip322-simple" || format == "bip322-full") {
      const auto selected = format == "bip322-simple" ? proofs::QuietProofBip322Format::kSimple : proofs::QuietProofBip322Format::kFull;
      imported = proofs::ImportQuietProofBip322Signature(request, selected, signature, &receipt.bytes, &error);
    } else { std::cerr << "unsupported signature transport for the request\n"; return kUnsupported; }
    if (!imported) {
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
