// Copyright (C) 2026 Plan-B Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#ifndef PRIVACY_PROOFS_ZK_LIB_POKC_CRT_GUARD_H_
#define PRIVACY_PROOFS_ZK_LIB_POKC_CRT_GUARD_H_

#include <cstddef>

#include "algebra/crt.h"

namespace proofs {

// The CRT auxiliary primes support transforms through order 2^22. Since that
// order is itself a power of two, the padded transform fits exactly when the
// unpadded block size does not exceed it.
inline bool PoKCCrtBlockSupported(size_t block_enc) {
  return block_enc <= crt::kOmegaOrder;
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_POKC_CRT_GUARD_H_
