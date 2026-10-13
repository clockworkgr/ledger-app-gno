#!/bin/bash -eu
# Builds the cargo-fuzz targets in fuzz/ for ClusterFuzzLite.
#
# The repository's .cargo/config.toml configures the device build (custom
# target, build-std) for everything below the root, so the host fuzzers are
# built from a copy outside it. fuzz/run.sh does the same locally.

copy="${WORK}/ledger-app-gno"
rm -rf "${copy}"
mkdir -p "${copy}/tests"
cp -R src host-tests fuzz "${copy}/"
cp -R tests/vectors "${copy}/tests/"

pushd "${copy}/fuzz"
cargo fuzz build --fuzz-dir . -O
popd

targets="fuzz_parser fuzz_der fuzz_source"
release="${copy}/fuzz/target/x86_64-unknown-linux-gnu/release"
corpus="${WORK}/corpus"
python3 fuzz/make_corpus.py . "${corpus}"
for t in ${targets}; do
  cp "${release}/${t}" "${OUT}/"
  (cd "${corpus}/${t}" && zip -q -r "${OUT}/${t}_seed_corpus.zip" .)
done
cp fuzz/fuzz_parser.dict "${OUT}/fuzz_parser.dict"
