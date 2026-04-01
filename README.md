# UPSI

**Efficient Updatable PSI from Asymmetric PSI and PSU**

This repository contains the implementation of **Our UPSI**, a cryptographic protocol described in the paper *"Efficient Updatable PSI from Asymmetric PSI and PSU"*.

### Paper

You can find the full paper [here](https://ieeexplore.ieee.org/abstract/document/11361182).

### Updates

We have fixed the security issues in our previous protocol caused by APSI.  
The new protocol has some performance loss compared to the previous one, but it remains the most efficient currently available.

The current PSU component incorporates the latest **two-sided PSU protocol** published at **EUROCRYPT 2026** by **Lucas Piske** and **Ni Trieu**, both from **Arizona State University**, available [here](https://eprint.iacr.org/2026/376). It is particularly effective for our protocol for two reasons. First, it natively provides a PSU protocol with **outputs for both parties**, which exactly matches the PSU functionality required by our construction. Second, it effectively protects the **exact input sizes** of both parties during PSU execution and leaks only **upper bounds**. This **completely fixes** the corresponding security issue in our protocol.

We also thank **Peihan Miao** for pointing out the substantive issue that the **input-size leakage of PSU exceeded the leakage permitted by the UPSI ideal functionality**.

### Docker

Build the Docker image from this repository root:

```bash
docker build --no-cache -f ./Dockerfile -t upsi:latest .
```

If you do not want to build locally, you can pull the prebuilt image directly:

```bash
docker pull shallmate/upsi:latest
```

and run it with:

```bash
docker run --rm shallmate/upsi:latest
```

To force a clean rebuild from scratch, remove the previous image first and then
disable the Docker layer cache:

```bash
docker image rm -f upsi:latest || true
docker build --no-cache --pull -f ./Dockerfile -t upsi:latest .
```

Run the UPSI binary:

```bash
docker run --rm upsi:latest
```

Open a shell in the container:

```bash
docker run -it --rm upsi:latest bash
```

If you want to shape loopback traffic with `tc` inside the container, start it
with `NET_ADMIN`:

```bash
docker run -it --rm --cap-add=NET_ADMIN upsi:latest bash
```

### PSU Backend

The PSU backend is currently selected at compile time in
`examples/upsi/main.cc`:

```cpp
constexpr PsuProtocol kUpSiPsuProtocol = PsuProtocol::kKrtw;
```

Supported backends:

- `PsuProtocol::kKrtw`
- `PsuProtocol::kIblt`

To switch the backend, edit that constant and rebuild:

```bash
bazel build //examples/upsi:upsi
```

The default `main()` in this directory runs `RunUPSIv1()`, so the selected PSU
backend applies to the PSU calls inside the UPSI online phase.

### Network Emulation

The helper script `examples/upsi/network_setup.sh` configures `tc/netem` on
`lo`. This is useful when running experiments inside Docker, since RR22, PSU,
and APSI traffic all use loopback in the current `upsi` setup.

Usage:

```bash
./network_setup.sh apply <rtt_ms> <rate> [dev]
./network_setup.sh show [dev]
./network_setup.sh clear [dev]
```

Examples:

```bash
./network_setup.sh apply 80 5
./network_setup.sh show
./network_setup.sh clear
```

Notes:

- The script treats the input latency as RTT, so `apply 80 5` becomes roughly
  `40 ms` one-way delay and `5 mbit` rate on `lo`.
- A plain numeric rate such as `5` is interpreted as `5mbit`.
- Applying `tc` requires `root` or `CAP_NET_ADMIN` in the target namespace.

A typical workflow inside the runtime container is:

```bash
./network_setup.sh apply 80 5
./upsi
./network_setup.sh clear
```

### Benchmark Script

The repository also provides a helper script for repeated benchmark runs:

```bash
./run_benchmarks.sh
```

By default it:

- builds `//examples/upsi:upsi`
- runs both PSU backends: `krtw`, `iblt`
- runs four scenarios: `LAN`, `WAN_200Mbps`, `WAN_50Mbps`, `WAN_5Mbps`
- repeats each backend/scenario pair `5` times
- writes logs under `benchmark_logs/<timestamp>/`

Common options:

```bash
./run_benchmarks.sh --help
./run_benchmarks.sh --backends=krtw --scenarios=WAN_5Mbps --repeats=1
./run_benchmarks.sh --backends=krtw,iblt --scenarios=LAN,WAN_200Mbps --repeats=3
./run_benchmarks.sh --skip-build
./run_benchmarks.sh --output-dir=./benchmark_logs/manual_run
```

Main arguments:

- `--repeats=N`: number of runs per backend/scenario pair
- `--backends=a,b`: choose from `krtw`, `iblt`
- `--scenarios=a,b`: choose from `LAN`, `WAN_200Mbps`, `WAN_50Mbps`, `WAN_5Mbps`
- `--skip-build`: reuse the existing `bazel-bin/examples/upsi/upsi`
- `--output-dir=PATH`: choose where logs and summaries are written

Outputs:

- `execution.log`: high-level execution trace
- `details.tsv`: per-run metrics and log paths
- `summary.tsv`: aggregate numeric summary
- `summary.md`: markdown table with aggregate and per-run results
- `runs/*.log`: raw stdout/stderr for each benchmark run

Notes:

- The script is intended to run from a source checkout, not from the minimal
  published runtime image.
- It configures `tc` on `lo` by itself via `network_setup.sh`.
- If you are not root, it will try to re-exec itself through `unshare -Urn`.
- The current IBLT PSU path uses internal local sockets, so WAN shaping does
  not fully cover the IBLT PSU exchange itself.

### Modifying APSI Source

This repository links APSI through the `local_apsi` repository declared in
`WORKSPACE`. By default it points to a local install prefix under:

```bash
third_party/local_apsi_fixed
```

This makes it possible to patch APSI locally without modifying `/usr/local`.

### Why APSI Needs a Local Patch

The default `main()` in this directory runs `RunUPSIv1()`. That path performs
deletions in the APSI sender database before the online UPSI phase. In code
terms, it deletes `X^-` and `Y^-` from APSI before inserting the fresh updates.

With upstream APSI `v0.11.0`, this delete path can occasionally abort with:

```text
terminate called after throwing an instance of 'std::logic_error'
  what():  failed to remove item
```

The practical reason is that APSI's `dispatch_remove` implementation launches
worker tasks that capture `bundle_idx` by reference. Under concurrency, a worker
can observe the wrong bundle index and try to remove an item from the wrong
bundle, which triggers `failed to remove item` even when the benchmark logic is
deleting items that really are present in the database.

In our setup, the fix is to capture `bundle_idx` by value instead:

```cpp
// before
futures[future_idx++] = tpm.thread_pool().enqueue([&]() {

// after
futures[future_idx++] = tpm.thread_pool().enqueue([&, bundle_idx]() {
```

The relevant APSI file is:

```text
sender/apsi/sender_db.cpp
```

Typical workflow:

1. Edit your APSI source tree.
2. Rebuild and install APSI into `third_party/local_apsi_fixed`.
3. Rebuild `upsi` with Bazel.

Example:

```bash
cmake -S /path/to/APSI-0.11.0 \
  -B /path/to/APSI-0.11.0/build-fixed \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/path/to/yacl/third_party/local_apsi_fixed \
  -DAPSI_BUILD_TESTS=OFF \
  -DAPSI_BUILD_CLI=OFF

cmake --build /path/to/APSI-0.11.0/build-fixed --target install -j$(nproc)

bazel build //examples/upsi:upsi
```

If you want to apply the `bundle_idx` fix manually, edit
`sender/apsi/sender_db.cpp` first and then rebuild/install APSI as above.

If you want to use a different APSI install prefix, update the `local_apsi`
`path` in `WORKSPACE` accordingly and rebuild.

### APSI in Docker

The Dockerfile in this directory already applies the same APSI fix during image
build:

1. Clone APSI `v0.11.0`
2. Patch `sender/apsi/sender_db.cpp`
3. Install the result into `third_party/local_apsi_fixed`
4. Build `//examples/upsi:upsi`

So if you build the image with:

```bash
docker build --no-cache --pull -f ./Dockerfile -t upsi:latest .
```

the resulting container already contains the patched APSI used by `RunUPSIv1()`.
If you want to try a different APSI patch, edit the APSI patch step in
`Dockerfile`, then rebuild the image from scratch.

### NOTE

If you encounter any problems when using this repository, you can ask questions about the issues or contact me directly at gw_ling@sjtu.edu.cn.
