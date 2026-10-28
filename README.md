# UPSI

Implementation of **Efficient Updatable PSI from Asymmetric PSI and PSU**.

[Paper](https://ieeexplore.ieee.org/abstract/document/11361182)

## Installation

Requires Linux x86-64, an AES/AVX2-capable CPU, GCC 13+, and CMake 3.25+.
On Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git autoconf automake libtool \
  pkg-config curl unzip zip python3 ninja-build

git clone https://github.com/ShallMate/upsi.git
cd upsi
JOBS=8 ./scripts/bootstrap_deps.sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Dependencies are downloaded and built automatically under `.deps/`.

## Run

Both parties run locally over TCP. The default uses KRTW with 2^20 items per
party and 512 insertions/deletions per round.

```bash
./build/bin/upsi --update-count=2
./build/bin/upsi --help
```

## Protocol update

The protocol-level fix uses a PSU functionality that returns the union to both
parties while hiding their exact input sizes. The current KRTW adapter provides
the union to both parties, but its size exchange still reveals input counts;
input-size hiding remains to be implemented.

## Acknowledgments

We thank Peihan Miao for pointing out that the original PSU input-size leakage
exceeded the leakage permitted by the UPSI ideal functionality.

Contact: gw_ling@sjtu.edu.cn.
