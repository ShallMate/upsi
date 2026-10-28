#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
deps=${UPSI_DEPS_DIR:-"$root/.deps"}
prefix="$deps/install"
jobs=${JOBS:-8}
mkdir -p "$deps/src" "$prefix"
fetch() {
  local name=$1 url=$2 rev=$3
  if [[ ! -d "$deps/src/$name/.git" ]]; then
    git clone "$url" "$deps/src/$name"
  fi
  git -C "$deps/src/$name" checkout --detach "$rev"
}
build() {
  local name=$1; shift
  cmake -S "$deps/src/$name" -B "$deps/build/$name" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_PREFIX_PATH="$prefix;${CMAKE_PREFIX_PATH:-}" "$@"
  cmake --build "$deps/build/$name" -j "$jobs"
  cmake --install "$deps/build/$name"
}
fetch gsl https://github.com/microsoft/GSL.git v4.2.0
build gsl -DGSL_TEST=OFF
fetch kuku https://github.com/microsoft/Kuku.git 1338c4ae2211ab4c739022ff57f48ce5a76531d5
build kuku -DKUKU_BUILD_EXAMPLES=OFF -DKUKU_BUILD_TESTS=OFF
fetch seal https://github.com/microsoft/SEAL.git ce53aa40969364f79599009bc8882f71fce0c13d
build seal -DSEAL_BUILD_DEPS=ON -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF \
  -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_BUILD_BENCH=OFF
fetch flatbuffers https://github.com/google/flatbuffers.git v25.2.10
build flatbuffers -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATLIB=ON
fetch jsoncpp https://github.com/open-source-parsers/jsoncpp.git 1.9.6
build jsoncpp -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DBUILD_SHARED_LIBS=OFF
fetch apsi https://github.com/microsoft/APSI.git 3f13fe6843e121da13adc66a250296bc96340cb0
build apsi -DAPSI_USE_ZMQ=OFF -DAPSI_BUILD_TESTS=OFF -DAPSI_BUILD_CLI=OFF
fetch libote https://github.com/osu-crypto/libOTe.git d55867114c78272be7142bd67ebdcb346fec8621
git -C "$deps/src/libote" submodule update --init --recursive
mkdir -p "$deps/build/libote/cryptoTools" "$deps/thirdparty"
# Download Boost with retry/resume before coproto's configure-time fetch.
if [[ ! -f "$deps/thirdparty/boost_1_86_0/bootstrap.sh" ]]; then
  archive="$deps/thirdparty/boost_1_86_0.tar.bz2"
  curl -fL --retry 5 --retry-delay 2 -C - \
    https://archives.boost.io/release/1.86.0/source/boost_1_86_0.tar.bz2 -o "$archive"
  printf '%s  %s\n' 1bed88e40401b2cb7a1f76d4bab499e352fa4d0c5f31c0dbae64e24d34d7513b "$archive" | sha256sum -c -
  tar -xjf "$archive" -C "$deps/thirdparty"
fi
build libote -USODIUM_INCLUDE_DIRS -USODIUM_LIBRARIES -DLIBOTE_BUILD_DIR="$deps/build/libote" \
  -DCRYPTOTOOLS_BUILD_DIR="$deps/build/libote/cryptoTools" \
  -DOC_THIRDPARTY_CLONE_DIR="$deps/thirdparty" \
  -DOC_THIRDPARTY_HINT="$prefix" -DOC_THIRDPARTY_INSTALL_PREFIX="$prefix" \
  -DPARALLEL_FETCH="$jobs" -DFETCH_SODIUM=ON -DFETCH_LIBDIVIDE=ON -DFETCH_BITPOLYMUL=ON -DFETCH_AUTO=ON -DENABLE_BOOST=ON -DENABLE_SODIUM=ON \
  -DENABLE_MRR=ON -DENABLE_KKRT=ON -DENABLE_SOFTSPOKEN_OT=ON \
  -DENABLE_SILENT_VOLE=ON -DENABLE_SILENTOT=ON -DENABLE_CIRCUITS=ON \
  -DENABLE_BITPOLYMUL=ON -DLIBOTE_STD_VER=20 -DMACORO_TESTS=OFF
printf '\nDependencies installed in %s\n' "$prefix"
