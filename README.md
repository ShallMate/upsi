# UPSI

**Efficient Updatable PSI from Asymmetric PSI and PSU**

This repository contains the implementation of **Our UPSI**, a cryptographic protocol described in the paper *"Efficient Updatable PSI from Asymmetric PSI and PSU"*.

### Paper

You can find the full paper [here](https://ieeexplore.ieee.org/abstract/document/11361182).

### Updates

We have fixed the security issues in our previous protocol caused by APSI.  
The new protocol has some performance loss compared to the previous one, but it remains the most efficient currently available.

### Docker

Build the Docker image from the `examples/upsi` directory:

```bash
docker build --no-cache -f ./Dockerfile -t upsi:latest .
```

Run the UPSI binary:

```bash
docker run --rm upsi:latest
```

Open a shell in the container:

```bash
docker run -it --rm upsi:latest bash
```

### NOTE

If you encounter any problems when using this repository, you can ask questions about the issues or contact me directly at gw_ling@sjtu.edu.cn.
