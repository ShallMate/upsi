# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ENV USE_BAZEL_VERSION=7.4.1
ENV PATH="/opt/bazelisk:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bash \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    libtool \
    m4 \
    make \
    ninja-build \
    patch \
    perl \
    pkg-config \
    python3 \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/bazelisk \
    && curl -fsSL -o /opt/bazelisk/bazel \
    https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
    && chmod +x /opt/bazelisk/bazel

WORKDIR /workspace
COPY . .

RUN --mount=type=cache,target=/root/.cache/bazel \
    --mount=type=cache,target=/root/.cache/bazelisk \
    bazel build --config=one //examples/upsi:upsi \
    && mkdir -p /workspace/docker-out \
    && cp -L bazel-bin/examples/upsi/upsi /workspace/docker-out/upsi

FROM ubuntu:22.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    iproute2 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /workspace/docker-out/upsi /app/upsi
COPY --from=builder /workspace/examples/upsi/parameters /app/parameters
COPY --from=builder /workspace/examples/upsi/network_setup.sh /app/network_setup.sh

RUN chmod +x /app/network_setup.sh

CMD ["./upsi"]
