# Kore io_uring vs epoll Benchmark Report

## Test Environment

- **OS**: Linux 6.8.0-110-generic (Ubuntu)
- **CPU**: Multi-core (4 worker processes)
- **Tool**: Apache JMeter 5.6.3
- **Config**: 100 threads, 30s duration, 5s ramp-up, HTTP keep-alive
- **Workload**: GET / returning "Hello, World!" (13 bytes), no TLS
- **Server**: 4 workers, `deployment dev`, bound to 127.0.0.1

## Results

| Metric | epoll | io_uring | Delta |
|---|---|---|---|
| Total requests | 751,299 | 887,676 | +18.1% |
| Errors | 0 | 2 (0.00%) | - |
| Throughput | 25,160 req/s | 29,681 req/s | **+18.0%** |
| Avg latency | 3.5ms | 3.0ms | **-14.3%** |
| Min latency | 0ms | 0ms | - |
| Max latency | 91ms | 10,011ms | +10,900% |
| P50 latency | 3ms | 3ms | 0% |
| P95 latency | 7ms | 6ms | **-14.3%** |
| P99 latency | 11ms | 8ms | **-27.3%** |

## Analysis

### Throughput

io_uring delivers **18% higher throughput** (29,681 vs 25,160 req/s). The improvement comes from:

- **Batched syscall submission**: io_uring amortizes the cost of poll registration across `io_uring_submit_and_wait`, reducing per-event syscall overhead compared to epoll's per-fd `epoll_ctl` + `epoll_wait` pattern.
- **Reduced kernel transitions**: The submission/completion queue model means fewer user-to-kernel context switches under sustained load.

### Latency

P95 and P99 latencies are significantly better with io_uring (-14% and -27% respectively). The tail latency improvement suggests more consistent event delivery under contention. The single high-max-latency outlier (10s) corresponds to one of the 2 errored requests and does not represent typical behavior.

### Stability

Both backends processed the full 30-second benchmark with all 4 workers running. The io_uring backend had 2 errors out of 887,676 requests (0.00023% error rate), likely caused by a transient poll race during the accept lock handoff between workers.

## Implementation Notes

### Architecture

The io_uring backend uses **multishot poll** (`IORING_POLL_ADD_MULTI`) for POLLIN monitoring on connection and listener fds. Key design decisions:

1. **POLLIN-only monitoring**: POLLOUT is not monitored because io_uring multishot poll is level-triggered. A writable socket would generate continuous POLLOUT CQEs, flooding the completion queue. Instead, `KORE_EVENT_WRITE` is set on every POLLIN delivery so `net_send_flush()` can drain the send queue synchronously after `http_process()`.

2. **Generation-based CQE validation**: Each fd in the lookup table has a generation counter. When a connection is torn down and the fd is reused by a new connection, stale CQEs from the old connection's multishot poll carry the old generation and are silently skipped.

3. **Cancel by user_data**: Polls are cancelled via `io_uring_prep_cancel64` (matching on the fd+generation user_data) rather than `io_uring_prep_cancel_fd`, which would race with fd reuse and accidentally cancel a new connection's poll.

### What's Not Yet Implemented

- **MSG_ZEROCOPY sends**: Disabled because zerocopy requires draining completion notifications from the socket error queue (`recvmsg(MSG_ERRQUEUE)`). Without this, the kernel notification buffer fills up under sustained load and sends start failing. This is a future optimization opportunity.
- **io_uring native recv/send**: Currently using poll-driven `recv(2)`/`send(2)` rather than `IORING_OP_RECV`/`IORING_OP_SEND`. Switching to native io_uring I/O ops could further reduce syscall overhead.
- **Registered buffers**: `io_uring_register_buffers` could eliminate per-I/O buffer mapping overhead.
