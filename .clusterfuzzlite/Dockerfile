FROM gcr.io/oss-fuzz-base/base-builder-rust:v1

COPY . $SRC/ledger-app-gno
WORKDIR $SRC/ledger-app-gno
COPY .clusterfuzzlite/build.sh $SRC/
