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

Build the Docker image from the repository root:

```bash
docker build --no-cache -f examples/upsi/Dockerfile -t upsi:latest .
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

### Modifying APSI Source

This repository links APSI through the `local_apsi` repository declared in
`WORKSPACE`. By default it points to a local install prefix under:

```bash
third_party/local_apsi_fixed
```

This makes it possible to patch APSI locally without modifying `/usr/local`.

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

If you want to use a different APSI install prefix, update the `local_apsi`
`path` in `WORKSPACE` accordingly and rebuild.

For example, if you are investigating the APSI `failed to remove item` issue,
the relevant implementation is in `sender/apsi/sender_db.cpp`. A known fix is
to make the remove-worker task capture `bundle_idx` by value instead of by
reference in `dispatch_remove`.

### NOTE

If you encounter any problems when using this repository, you can ask questions about the issues or contact me directly at gw_ling@sjtu.edu.cn.
