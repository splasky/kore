# Web Framework Benchmark Results

Date: 2026-04-20

## Test Environment
- Container runtime: podman (instead of docker)
- Network: host mode

## Results (requests/sec, higher is better)

### Container (podman)

| Framework | Language | 64 conn | 256 conn | 512 conn |
|------------|------|---------|----------|----------|
| rust/ohkami-tokio | Rust | 166,982 | 220,725 | 211,092 |
| cpp/drogon | C++ | 179,386 | 207,869 | 204,950 |
| c/agoo-c | C | 94,676 | 144,673 | 181,966 |
| c/kore (epoll) | C | 76,804 | 73,547 | 60,411 |

All container tests: **100% success rate**

### Native (io_uring, on host)

| Framework | Language | 64 conn | 256 conn | 512 conn |
|------------|------|---------|----------|----------|
| c/kore (io_uring) | C | 101,646 | 100,379 | 88,370 |

Note: kore io_uring on host uses `-fnr` flags to disable privsep (chroot/user switching)

## Frameworks Tested
1. **rust/ohkami-tokio** - Rust web framework using tokio
2. **cpp/drogon** - C++ web framework
3. **c/agoo-c** - C web framework
4. **c/kore** - C web framework (io_uring backend)

## Notes
- kore runs on port 3002 (others on 3000)
- kore container version uses epoll (no io_uring due to container restrictions)
- kore native uses io_uring with `-fnr` flags for privsep bypass
- All tests run with 15s duration per concurrency level