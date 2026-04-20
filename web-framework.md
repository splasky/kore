# Web Framework Benchmark Results

Date: 2026-04-20

## Test Environment
- Container runtime: podman (instead of docker)
- Network: host mode

## Results (requests/sec, higher is better)

| Framework | Language | 64 conn | 256 conn | 512 conn |
|------------|------|---------|----------|----------|
| rust/ohkami-tokio | Rust | 166,982 | 220,725 | 211,092 |
| cpp/drogon | C++ | 179,386 | 207,869 | 204,950 |
| c/agoo-c | C | 94,676 | 144,673 | 181,966 |
| c/kore | C | 76,804 | 73,547 | 60,411 |

All frameworks: **100% success rate**

## Frameworks Tested
1. **rust/ohkami-tokio** - Rust web framework using tokio
2. **cpp/drogon** - C++ web framework
3. **c/agoo-c** - C web framework
4. **c/kore** - C web framework (uses port 3002, others use 3000)

## Notes
- kore runs on port 3002 (others on 3000)
- kore built with TLS_BACKEND=none and no io_uring (epoll only) for container compatibility
- All tests run with 15s duration per concurrency level