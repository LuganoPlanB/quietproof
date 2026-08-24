#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PROJECT_ROOT
REPOSITORY_ROOT="$(cd -- "${PROJECT_ROOT}/../.." && pwd -P)"
readonly REPOSITORY_ROOT

if [[ -n "${LONGFELLOW_ZK_INCLUDE_DIR:-}" ]]; then
  base_include=${LONGFELLOW_ZK_INCLUDE_DIR}
elif [[ -d "${REPOSITORY_ROOT}/src" ]]; then
  base_include=${REPOSITORY_ROOT}/src
else
  printf '%s\n' \
    'set LONGFELLOW_ZK_INCLUDE_DIR to the installed longfellow-zk include directory' >&2
  exit 2
fi
readonly base_include
cd -- "${PROJECT_ROOT}"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required static-analysis tool is unavailable: %s\n' "$1" >&2
    exit 69
  }
}

require_tool clang-tidy
require_tool cppcheck
require_tool shellcheck

readonly checks='clang-analyzer-*,bugprone-*,performance-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier'
readonly header_filter="^${PROJECT_ROOT}/(include/(quietproof|pokc|circuit)|src|tests)/"
readonly translation_units=(
  tests/quietproof/protocol_test.cc
  tests/quietproof/integration_test.cc
  tests/quietproof/pokc_sage_vector_test.cc
  src/quietproof_main.cc
)

for source in "${translation_units[@]}"; do
  clang-tidy \
    -checks="${checks}" \
    -header-filter="${header_filter}" \
    -warnings-as-errors='clang-analyzer-*,bugprone-*' \
    "${source}" -- \
    -std=c++20 -I"${base_include}" -Iinclude
done

cppcheck \
  --enable=warning,performance,portability \
  --language=c++ \
  --std=c++20 \
  --inline-suppr \
  --relative-paths=. \
  --suppress=missingIncludeSystem \
  --suppress=unmatchedSuppression \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=toomanyconfigs \
  "--suppress=*:${base_include}/util/*" \
  "--suppress=*:${base_include}/circuits/*" \
  "--suppress=*:${base_include}/random/*" \
  "--suppress=*:${base_include}/algebra/*" \
  "--suppress=*:${base_include}/zk/*" \
  "--suppress=*:${base_include}/sumcheck/*" \
  "--suppress=returnByReference:${base_include}/arrays/dense.h" \
  "--suppress=shiftTooManyBitsSigned:${base_include}/proto/circuit_writer.h" \
  '--suppress=*:include/cli/json.hpp' \
  --error-exitcode=1 \
  -I"${base_include}" -Iinclude \
  include/quietproof/statement.h \
  include/quietproof/envelope.h \
  include/quietproof/chain_state.h \
  include/quietproof/bitcoin_core.h \
  include/quietproof/nonce_store.h \
  include/quietproof/verifier.h \
  src/quietproof_main.cc

shellcheck tests/quietproof/cli_test.sh \
  scripts/run_pokc_sage.sh \
  scripts/run_quietproof_static_analysis.sh
printf 'QuietProof static analysis passed\n'
