#!/usr/bin/env bash
# Runs a fuzz target locally: ./fuzz/run.sh <target> [seconds]
#
# The repository's .cargo/config.toml builds for the device (custom target,
# build-std), and cargo applies it to every build below the repository root.
# The fuzzers are host builds, so they are built from a copy outside the tree,
# exactly as .clusterfuzzlite/build.sh does in CI. Needs rustup, a nightly
# toolchain (FUZZ_TOOLCHAIN, default "nightly") and cargo-fuzz on PATH. The
# corpus and any crash artifacts are kept in fuzz/work/.
set -euo pipefail

target="${1:?usage: run.sh <fuzz_parser|fuzz_der|fuzz_source> [seconds]}"
seconds="${2:-60}"
toolchain="${FUZZ_TOOLCHAIN:-nightly}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="${repo}/fuzz/work"
copy="$(mktemp -d)"
trap 'rm -rf "${copy}"' EXIT

mkdir -p "${copy}/tests" "${work}"
cp -R "${repo}/src" "${repo}/host-tests" "${repo}/fuzz" "${copy}/"
cp -R "${repo}/tests/vectors" "${copy}/tests/"
rm -rf "${copy}/fuzz/work" "${copy}/host-tests/target"

python3 "${repo}/fuzz/make_corpus.py" "${repo}" "${work}/corpus"
dict=()
[[ "${target}" == fuzz_parser ]] && dict=("-dict=${copy}/fuzz/fuzz_parser.dict")

# Put the toolchain first on PATH: cargo-fuzz calls `cargo` and `rustc` by name.
PATH="$(dirname "$(rustup which cargo --toolchain "${toolchain}")"):${PATH}"
export PATH

cd "${copy}/fuzz"
cargo fuzz run --fuzz-dir . "${target}" "${work}/corpus/${target}" -- \
  -max_total_time="${seconds}" -artifact_prefix="${work}/" "${dict[@]}"
