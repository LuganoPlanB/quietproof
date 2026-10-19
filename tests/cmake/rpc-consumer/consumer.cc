#include "quietproof/bitcoin_rpc.h"

#include <type_traits>

// Exercise link-only curl transitivity without exposing its headers or types.
extern "C" const char* curl_version();
extern "C" int CheckRpcConsumer() {
  using namespace proofs;
  static_assert(!std::is_default_constructible_v<BitcoinCoreRpcConfig>);
  static_assert(!std::is_copy_constructible_v<BitcoinCoreRpc>);
  BitcoinCoreRpc rpc(BitcoinCoreRpcConfig{QuietProofNetwork::kRegtest});
  BitcoinUtxoDiscovery output;
  output.observed_height = 42;
  BitcoinRpcError error;
  if (rpc.Discover(BitcoinUtxoQuery{"address"}, &output, &error) ||
      output.observed_height != 42 || error.code == BitcoinRpcErrorCode::kNone)
    return 1;
  QuietProofChainRequest request{};
  request.network = QuietProofNetwork::kRegtest;
  if (rpc.kind() != QuietProofProviderKind::kCurrentTip ||
      rpc.Lookup(request).status != QuietProofChainStatus::kUnavailable)
    return 2;
  return curl_version() ? 0 : 3;
}
