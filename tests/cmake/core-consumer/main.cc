#include "quietproof/challenge.h"
#include "quietproof/bitcoin_core.h"
int main() {
  proofs::QuietProofChallengeOptions options;
  return static_cast<unsigned>(options.network) == 0xff ? 0 : 1;
}
