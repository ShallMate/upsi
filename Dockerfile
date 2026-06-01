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
ARG YACL_REF=upsi
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
import re
from pathlib import Path

p = Path("/workspace/bazel/repositories.bzl")
s = p.read_text()
old_blake3 = "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.5.1.tar.gz"
new_blake3 = "https://codeload.github.com/BLAKE3-team/BLAKE3/tar.gz/refs/tags/1.5.1"
if old_blake3 in s:
    s = s.replace(old_blake3, new_blake3)
elif new_blake3 not in s:
    raise SystemExit("BLAKE3 archive URL marker not found")

if '        type = "tar.gz",\n' not in s:
    needle = '        build_file = "@yacl//bazel:blake3.BUILD",\n'
    if needle not in s:
        raise SystemExit("BLAKE3 build_file marker not found")
    s = s.replace(
        needle,
        '        build_file = "@yacl//bazel:blake3.BUILD",\n        type = "tar.gz",\n',
        1,
    )

s, n = re.subn(
    r'(name\s*=\s*"local_volepsi"\s*,[\s\S]*?)(\n\s*)path\s*=\s*"[^"]*"',
    r'\1\2path = "third_party/local_volepsi"',
    s,
    count=1,
)
if n == 0 and 'name = "local_volepsi"' in s and 'path = "third_party/local_volepsi"' not in s:
    raise SystemExit("local_volepsi path marker not found in /workspace/bazel/repositories.bzl")

p.write_text(s)
PY
RUN rm -rf /workspace/examples/upsi
COPY . /workspace/examples/upsi

# Add an opt-in portable base OT path for Docker builds. This keeps the image
# runnable on hosts where the default Linux x86 asm base OT crashes before the
# selected PSU backend is reached.
RUN python3 - <<'PY'
from pathlib import Path

def replace_once(path, old, new, desc):
    p = Path(path)
    s = p.read_text()
    if new in s:
        return
    if old not in s:
        raise SystemExit(f"{desc} marker not found in {path}")
    p.write_text(s.replace(old, new, 1))

replace_once(
    "/workspace/yacl/kernel/algorithms/base_ot.h",
    '#if defined(__linux__) && defined(__x86_64)\n'
    '#include "yacl/kernel/algorithms/x86_asm_ot_interface.h"\n'
    '#else\n'
    '#include "yacl/kernel/algorithms/portable_ot_interface.h"\n'
    '#endif\n',
    '#if defined(YACL_FORCE_PORTABLE_OT)\n'
    '#include "yacl/kernel/algorithms/portable_ot_interface.h"\n'
    '#elif defined(__linux__) && defined(__x86_64)\n'
    '#include "yacl/kernel/algorithms/x86_asm_ot_interface.h"\n'
    '#else\n'
    '#include "yacl/kernel/algorithms/portable_ot_interface.h"\n'
    '#endif\n',
    "base_ot.h portable OT include",
)

replace_once(
    "/workspace/yacl/kernel/algorithms/base_ot.cc",
    '#if defined(__linux__) && defined(__x86_64)\n'
    '  // x86 asm ot does not support macOS\n'
    '  return std::make_unique<X86AsmOtInterface>();\n'
    '#else\n'
    '  return std::make_unique<PortableOtInterface>();\n'
    '#endif\n',
    '#if defined(YACL_FORCE_PORTABLE_OT)\n'
    '  return std::make_unique<PortableOtInterface>();\n'
    '#elif defined(__linux__) && defined(__x86_64)\n'
    '  // x86 asm ot does not support macOS\n'
    '  return std::make_unique<X86AsmOtInterface>();\n'
    '#else\n'
    '  return std::make_unique<PortableOtInterface>();\n'
    '#endif\n',
    "base_ot.cc portable OT branch",
)

replace_once(
    "/workspace/yacl/kernel/algorithms/BUILD.bazel",
    '        "@com_google_absl//absl/types:span",\n'
    '    ] + select({\n',
    '        "@com_google_absl//absl/types:span",\n'
    '        ":portable_ot_interface",\n'
    '    ] + select({\n',
    "base_ot portable OT dependency",
)

replace_once(
    "/workspace/yacl/kernel/algorithms/BUILD.bazel",
    '        "//conditions:default": [\n'
    '            ":portable_ot_interface",\n'
    '        ],\n',
    '        "//conditions:default": [],\n',
    "base_ot default portable OT dependency",
)
PY

# volePSI's CMake probes Boost when VOLE_PSI_ENABLE_BOOST=ON.
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
if old in s:
    s = s.replace(old, new, 1)
elif new not in s:
    raise SystemExit("APSI remove-worker patch point not found")
p.write_text(s)
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
import re
from pathlib import Path

p = Path("/workspace/WORKSPACE")
s = p.read_text()

s, n = re.subn(
    r'(name\s*=\s*"local_volepsi"\s*,[\s\S]*?)(\n\s*)path\s*=\s*"[^"]*"',
    r'\1\2path = "third_party/local_volepsi"',
    s,
    count=1,
)
if n == 0 and 'path = "third_party/local_volepsi"' not in s:
    raise SystemExit("local_volepsi path marker not found in /workspace/WORKSPACE")

p.write_text(s)
PY

# Build the upsi example inside yacl without host bazelrc files.
# Disable Bzlmod so Bazel uses the repo's WORKSPACE-based external dependency setup.
RUN bazel --bazelrc=/dev/null build \
    --noenable_bzlmod \
    --cxxopt=-std=c++17 \
    --host_cxxopt=-std=c++17 \
    --copt=-DYACL_FORCE_PORTABLE_OT \
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
