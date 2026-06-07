# UPSI

**Efficient Updatable PSI from Asymmetric PSI and PSU**

This directory contains the UPSI example used by YACL. The implementation is
for the paper *Efficient Updatable PSI from Asymmetric PSI and PSU*.

Paper: <https://ieeexplore.ieee.org/abstract/document/11361182>

## Build

Build from the YACL repository root:

```bash
bazel build --config=one //examples/upsi:upsi
```

Run the binary:

```bash
bazel-bin/examples/upsi/upsi
```

The repository default also works:

```bash
bazel build
```

That builds the core YACL targets and all examples declared in the default
target file.

## Dependencies

YACL is self-contained through Bazel. You do not need to manually install the
C++ dependencies used by this example, such as APSI, SEAL, Kuku, libOTe,
volePSI, NTL, GMP, or ZeroMQ.

In particular:

- Do not install these libraries into `/usr/local` for this example.
- Do not add host-local include or library paths.
- Use the dependency declarations in `bazel/repositories.bzl`.
- Bazel writes build outputs under `bazel-bin`, `bazel-out`, and its external
  repository cache.

For downstream use, load YACL's repository setup from `bazel/repositories.bzl`.
Examples can remain optional for library consumers:

```python
load("@yacl//bazel:repositories.bzl", "yacl_deps")

yacl_deps(
    include_examples = False,
)
```

Inside this checkout, `WORKSPACE` enables examples so `bazel build` builds them
by default.

## PSU Backend

The default UPSI binary uses the KRTW PSU path:

```bash
bazel-bin/examples/upsi/upsi --psu-backend=krtw
```

You can also set the backend through an environment variable:

```bash
UPSI_PSU_BACKEND=krtw bazel-bin/examples/upsi/upsi
```

The IBLT PSU implementation is kept under `examples/upsi/psu` and can be built
or tested through its own targets while working on that backend.

## Network Emulation

`network_setup.sh` configures `tc/netem` on loopback for local experiments:

```bash
cd examples/upsi
./network_setup.sh apply <rtt_ms> <rate> [dev]
./network_setup.sh show [dev]
./network_setup.sh clear [dev]
```

Example:

```bash
./network_setup.sh apply 80 5
../../bazel-bin/examples/upsi/upsi
./network_setup.sh clear
```

A plain numeric rate such as `5` means `5mbit`. Applying `tc` requires root or
`CAP_NET_ADMIN`.

## Benchmarks

The benchmark helper is optional:

```bash
cd examples/upsi
./run_benchmarks.sh --backends=krtw --scenarios=LAN --repeats=1
```

Useful options:

```bash
./run_benchmarks.sh --help
./run_benchmarks.sh --backends=krtw --scenarios=WAN_5Mbps --repeats=1
./run_benchmarks.sh --skip-build
./run_benchmarks.sh --output-dir=./benchmark_logs/manual_run
```

Outputs are written under `benchmark_logs/<timestamp>/`.

## Docker

Docker is optional. The normal path is the Bazel build above.

To build the image from the YACL repository root:

```bash
docker build -f examples/upsi/Dockerfile -t upsi:latest .
```

Run it:

```bash
docker run --rm upsi:latest
```

If you need traffic shaping inside the container:

```bash
docker run -it --rm --cap-add=NET_ADMIN upsi:latest bash
```

## Notes

The protocol update fixes the earlier APSI-related leakage issue by using a PSU
functionality that provides outputs to both parties and hides exact input sizes.
We also thank Peihan Miao for pointing out that the original PSU input-size
leakage exceeded the leakage permitted by the UPSI ideal functionality.

For questions, contact gw_ling@sjtu.edu.cn.
