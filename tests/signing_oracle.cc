// Test-only public parse/verify oracle, linked only when Core32 tests are enabled.
// No signing, secret-key, recovery or application/SDK circuit code is used here.
#include <secp256k1.h>

#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::vector<unsigned char> Hex(std::string_view text) {
  if (text.size() % 2 != 0) throw std::runtime_error("invalid hex");
  auto nibble = [](char c) -> unsigned char {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    throw std::runtime_error("invalid hex");
  };
  std::vector<unsigned char> out;
  for (size_t i = 0; i < text.size(); i += 2)
    out.push_back((nibble(text[i]) << 4) | nibble(text[i + 1]));
  return out;
}

bool Verify(std::string_view digest_hex, std::string_view der_hex,
            std::string_view pubkey_hex) {
  const auto digest = Hex(digest_hex), der = Hex(der_hex), pubkey = Hex(pubkey_hex);
  if (digest.size() != 32 || der.empty() || der.size() > 72 ||
      pubkey.size() != 33 || (pubkey[0] != 2 && pubkey[0] != 3)) return false;
  const std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>
      ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE), secp256k1_context_destroy);
  secp256k1_pubkey key;
  secp256k1_ecdsa_signature signature;
  if (!secp256k1_ec_pubkey_parse(ctx.get(), &key, pubkey.data(), pubkey.size()) ||
      !secp256k1_ecdsa_signature_parse_der(ctx.get(), &signature, der.data(), der.size()))
    return false;
  // Roundtrip detects noncanonical DER; never silently normalize high S.
  std::array<unsigned char, 72> canonical{};
  size_t length = canonical.size();
  if (!secp256k1_ecdsa_signature_serialize_der(ctx.get(), canonical.data(), &length, &signature) ||
      std::vector<unsigned char>(canonical.begin(), canonical.begin() + length) != der ||
      secp256k1_ecdsa_signature_normalize(ctx.get(), nullptr, &signature)) return false;
  return secp256k1_ecdsa_verify(ctx.get(), &signature, digest.data(), &key) == 1;
}

bool SelfTest() {
  // Public mathematical fixture: d=1, k=1, z=1, r=x(G), s=r+1.
  // This is deliberately insecure fixture arithmetic, never a wallet signature.
  const std::string z = std::string(63, '0') + "1";
  const std::string key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const std::string der = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                          "022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799";
  return Verify(z, der, key) &&
         !Verify(std::string(63, '0') + "2", der, key) &&
         !Verify(z, der, "03" + key.substr(2)) &&
         !Verify(z, der + "00", key) &&
         !Verify(z, "3000", key) &&
         !Verify(z, der, "02" + std::string(64, 'f')) &&
         !Verify(z, der, "04" + key.substr(2));
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
      if (!SelfTest()) throw std::runtime_error("oracle self-test failed");
      std::cout << "oracle: 7 checks passed\n";
      return 0;
    }
    if (argc != 4) throw std::runtime_error("expected digest, DER signature, compressed public key");
    const bool valid = Verify(argv[1], argv[2], argv[3]);
    std::cout << (valid ? "valid\n" : "invalid\n");
    return valid ? 0 : 1;
  } catch (const std::exception&) {
    std::cerr << "oracle: invalid invocation or input\n";
    return 2;
  }
}
