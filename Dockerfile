# syntax=docker/dockerfile:1

# Builder stage: install deps, build required libraries, then build the yacl upsi binary.
FROM ubuntu:22.04 AS builder

ARG BAZEL_VERSION=6.4.1
ARG SEAL_VERSION=4.1
ARG KUKU_VERSION=2.1
ARG APSI_VERSION=0.11
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl git python3 python3-pip \
    cmake ninja-build pkg-config unzip wget gnupg lsb-release \
    libssl-dev libgflags-dev libunwind-dev libgoogle-glog-dev \
    libjsoncpp-dev libzmq3-dev liblog4cplus-dev \
    && rm -rf /var/lib/apt/lists/*

# Install bazel (using upstream binary distribution)
RUN curl -fsSL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64 -o /usr/local/bin/bazel \
    && chmod +x /usr/local/bin/bazel

WORKDIR /tmp

# Install Microsoft SEAL (must provide /usr/local/include/SEAL-4.1 and /usr/local/lib/libseal-4.1.a)
RUN git clone --depth 1 --branch v${SEAL_VERSION} https://github.com/microsoft/SEAL.git && \
    mkdir -p SEAL/build && cd SEAL/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_INSTALL=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Install Kuku (must provide /usr/local/include/Kuku-2.1 and /usr/local/lib/libkuku-2.1.a)
RUN git clone --depth 1 --branch v${KUKU_VERSION} https://github.com/microsoft/Kuku.git && \
    mkdir -p Kuku/build && cd Kuku/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Install APSI (must provide /usr/local/include/APSI-0.11 and /usr/local/lib/libapsi-0.11.a)
RUN git clone --depth 1 --branch v${APSI_VERSION} https://github.com/microsoft/apsi.git && \
    mkdir -p apsi/build && cd apsi/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Build the upsi example in the yacl repo (only depends on examples/upsi + yacl libs)
WORKDIR /workspace
COPY . .
RUN bazel build //examples/upsi:upsi

# Final runtime image
FROM ubuntu:22.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libgoogle-glog0v5 libunwind8 libzmq5 liblog4cplus-2.0-1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /workspace/bazel-bin/examples/upsi/upsi /app/upsi

ENTRYPOINT ["./upsi"]
