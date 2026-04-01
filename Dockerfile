# syntax=docker/dockerfile:1

# Builder stage: install deps, build required libraries, then build the latest
# pushed yacl + upsi sources.
FROM ubuntu:22.04 AS builder

ARG SEAL_VERSION=4.1.2
ARG KUKU_VERSION=2.1.0
ARG APSI_VERSION=0.11.0
ARG VOLEPSI_REPO=https://github.com/Visa-Research/volepsi.git
ARG VOLEPSI_REF=ed943f5
ARG YACL_REPO=https://github.com/ShallMate/yacl.git
ARG YACL_REF=f978244
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates curl git libtool \
    python3 python3-pip \
    cmake ninja-build pkg-config unzip wget gnupg lsb-release \
    libssl-dev libgflags-dev libunwind-dev libgoogle-glog-dev \
    libjsoncpp-dev libzmq3-dev liblog4cplus-dev \
    && rm -rf /var/lib/apt/lists/*

# Bazel's local_log4cplus repository points at /usr/local, but Ubuntu installs
# the development headers and linker symlink under /usr.
RUN mkdir -p /usr/local/include /usr/local/lib && \
    ln -sf /usr/include/log4cplus /usr/local/include/log4cplus && \
    ln -sf /usr/lib/$(gcc -print-multiarch)/liblog4cplus.so /usr/local/lib/liblog4cplus.so

# jsoncpp on Ubuntu installs headers under /usr/include/jsoncpp; APSI expects /usr/local/include/json
# Build a static jsoncpp install in /usr/local to satisfy Bazel's local_jsoncpp repository.
RUN git clone --depth 1 --branch 1.9.5 https://github.com/open-source-parsers/jsoncpp.git /tmp/jsoncpp && \
    mkdir -p /tmp/jsoncpp/build && cd /tmp/jsoncpp/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install && \
    mkdir -p /usr/local/include/json && \
    ln -sf /usr/local/include/jsoncpp/json /usr/local/include/json

# jsoncpp on Ubuntu installs headers under /usr/include/jsoncpp; APSI expects /usr/include/json
RUN mkdir -p /usr/include/json && \
    ln -sf /usr/include/jsoncpp/json /usr/include/json

# Install cppzmq (C++ bindings for ZeroMQ) from source to provide CMake config
RUN git clone --depth 1 https://github.com/zeromq/cppzmq.git /tmp/cppzmq && \
    mkdir -p /tmp/cppzmq/build && cd /tmp/cppzmq/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Build and install Flatbuffers from source (provides correct CMake export)
RUN git clone --depth 1 --branch v1.12.0 https://github.com/google/flatbuffers.git /tmp/flatbuffers && \
    mkdir -p /tmp/flatbuffers/build && cd /tmp/flatbuffers/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATC=ON .. && \
    make -j$(nproc) && make install

# Install bazel via bazelisk.
RUN curl -fsSL -o /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel

# Pin Bazel 7 for this WORKSPACE-based repo. Bazel 8 requires additional Bzlmod migration work.
ENV USE_BAZEL_VERSION=7.4.1

WORKDIR /tmp

# Install Microsoft SEAL (must provide /usr/local/include/SEAL-4.1 and /usr/local/lib/libseal-4.1.a)
RUN git clone --depth 1 --branch v${SEAL_VERSION} https://github.com/microsoft/SEAL.git && \
    mkdir -p SEAL/build && cd SEAL/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_INSTALL=ON -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Install Kuku (must provide /usr/local/include/Kuku-2.1 and /usr/local/lib/libkuku-2.1.a)
RUN git clone --depth 1 --branch v${KUKU_VERSION} https://github.com/microsoft/Kuku.git && \
    mkdir -p Kuku/build && cd Kuku/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Build and install ZeroMQ from source so CMake find_package(ZeroMQ) works
RUN git clone --depth 1 --branch v4.3.4 https://github.com/zeromq/libzmq.git && \
    mkdir -p libzmq/build && cd libzmq/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

WORKDIR /workspace
RUN git clone ${YACL_REPO} . && git checkout ${YACL_REF}
RUN python3 - <<'PY'
from pathlib import Path

p = Path("/workspace/bazel/repositories.bzl")
s = p.read_text()
s = s.replace(
    "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.5.1.tar.gz",
    "https://codeload.github.com/BLAKE3-team/BLAKE3/tar.gz/refs/tags/1.5.1",
)
s = s.replace(
    '        build_file = "@yacl//bazel:blake3.BUILD",\n',
    '        build_file = "@yacl//bazel:blake3.BUILD",\n        type = "tar.gz",\n',
    1,
)
s = s.replace(
    '    path = "/home/lgw/sp26/mPSI/out/install/linux",\n',
    '    path = "third_party/local_volepsi",\n',
    1,
)
p.write_text(s)
PY
RUN rm -rf /workspace/examples/upsi
COPY . /workspace/examples/upsi

# simple_index.cc uses Boost header-only math/multiprecision components.
RUN apt-get update && apt-get install -y --no-install-recommends libboost-dev && \
    rm -rf /var/lib/apt/lists/*

# Build the volePSI install tree expected by the IBLT PSU backend.
RUN git clone ${VOLEPSI_REPO} /tmp/volepsi && \
    cd /tmp/volepsi && \
    git checkout ${VOLEPSI_REF} && \
    cmake -S . -B out/build/linux \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/workspace/third_party/local_volepsi \
      -DFETCH_AUTO=ON \
      -DVOLE_PSI_NO_SYSTEM_PATH=true \
      -DVOLE_PSI_ENABLE_BOOST=ON && \
    cmake --build out/build/linux --parallel $(nproc) && \
    cmake --install out/build/linux

# Build APSI into the workspace-local prefix expected by WORKSPACE.
RUN git clone --depth 1 --branch v${APSI_VERSION} https://github.com/microsoft/apsi.git /tmp/apsi && \
    python3 - <<'PY'
from pathlib import Path

p = Path("/tmp/apsi/sender/apsi/sender_db.cpp")
s = p.read_text()
old = '                    futures[future_idx++] = tpm.thread_pool().enqueue([&]() {\n'
new = '                    futures[future_idx++] = tpm.thread_pool().enqueue([&, bundle_idx]() {\n'
if old not in s:
    raise SystemExit("APSI remove-worker patch point not found")
p.write_text(s.replace(old, new, 1))
PY
RUN mkdir -p /workspace/third_party/local_apsi_fixed && \
    cmake -S /tmp/apsi -B /tmp/apsi/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/workspace/third_party/local_apsi_fixed \
      -DAPSI_BUILD_TESTS=OFF \
      -DAPSI_BUILD_CLI=OFF && \
    cmake --build /tmp/apsi/build --target install -j$(nproc)

# Ensure the cloned YACL workspace points local_volepsi at the in-image install
# tree instead of a host-specific absolute path.
RUN python3 - <<'PY'
from pathlib import Path

p = Path("/workspace/WORKSPACE")
s = p.read_text()
host_path = "/home/lgw/sp26/mPSI/out/install/linux"
image_path = "third_party/local_volepsi"

if host_path in s:
    s = s.replace(host_path, image_path)
elif image_path not in s:
    raise SystemExit("local_volepsi path marker not found in /workspace/WORKSPACE")

p.write_text(s)
PY

# Build the upsi example inside yacl without host bazelrc files.
# Disable Bzlmod so Bazel uses the repo's WORKSPACE-based external dependency setup.
RUN bazel --bazelrc=/dev/null build \
    --noenable_bzlmod \
    --cxxopt=-std=c++17 \
    --host_cxxopt=-std=c++17 \
    //examples/upsi:upsi

# Final runtime image
FROM ubuntu:22.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive

# Enable universe repo so log4cplus packages are available
RUN apt-get update && apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository universe && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates iproute2 libgoogle-glog0v5 libunwind8 libzmq5 liblog4cplus-2.0.5 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /workspace/bazel-bin/examples/upsi/upsi /app/upsi
COPY --from=builder /workspace/examples/upsi/parameters /app/parameters
COPY --from=builder /workspace/examples/upsi/network_setup.sh /app/network_setup.sh

RUN chmod +x /app/network_setup.sh

CMD ["./upsi"]
