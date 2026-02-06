# 010. Container-Native Logging Strategy

## Status
Accepted

## Context
The initial logging architecture included a local file sink (`logs/app.log`) with rotation and retention policies. While useful for local development, this approach violates the [Twelve-Factor App](https://12factor.net/logs) methodology and poses a security risk in containerized environments (Kubernetes, Docker), specifically **Disk Exhaustion (Finding #7)**.

Writing logs to the container's ephemeral filesystem can fill up the available storage, leading to:
- **Pod Eviction:** The node creates pressure on disk resources, causing the scheduler to evict the pod.
- **Container Crashes:** The application may crash if it cannot write to disk.
- **Loss of Observability:** Logs trapped in a crashed container's filesystem are often lost.

## Decision
We have decided to disable default file logging and strictly adhere to a container-native logging strategy.

### 1. Disable File Sinks
The application will no longer create a `logs/` directory or write to `logs/app.log` by default. This removes the risk of disk exhaustion caused by logging.

### 2. Standard Streams (Stdout/Stderr)
All logs will be directed to standard streams, which allows the container runtime (Docker, Containerd) and orchestration layer (Kubernetes) to capture, aggregate, and forward logs to a centralized logging system (e.g., Fluentd, Datadog, ELK, Splunk).

- **Human-Readable (Dev):** By default, logs are written to `sys.stderr` in a human-readable format with colors.
- **JSON (Prod):** When `COREASON_LOG_JSON=true` is set, logs are written to `sys.stdout` in structured JSON format, suitable for machine parsing.

### 3. OpenTelemetry Integration
The logging system maintains its integration with OpenTelemetry. Trace IDs and Span IDs are injected into the log records (both text and JSON) to ensure correlation between traces and logs.

## Consequences

### Positive
- **Security:** Eliminates the risk of disk exhaustion via logging (DoS vector).
- **Scalability:** Logging infrastructure is decoupled from the application. Aggregation is handled by the platform.
- **Compliance:** Aligns with Twelve-Factor App principles and container best practices.
- **Simplicity:** Removes code complexity related to file rotation, permissions, and directory management.

### Negative
- **Local Debugging:** Developers cannot simply `tail -f logs/app.log`. They must rely on capturing stdout/stderr (e.g., `docker logs -f <container>`).
- **Persistence:** Logs are ephemeral unless captured by an external system. This is standard behavior for containers but requires a configured logging backend for persistent storage.

## Implementation Details
The `src/coreason_identity/utils/logger.py` module has been refactored to:
1.  Remove `logger.add("logs/app.log", ...)`
2.  Remove `os.makedirs("logs")`
3.  Retain `logger.add(sys.stderr, ...)` and `logger.add(sys.stdout, ...)` based on `COREASON_LOG_JSON`.

## Testing Strategy
To ensure the stability and security of the logging configuration, the following test coverage is mandatory:

1.  **Security Verification:** `tests/test_logger_security.py` verifies that no file sinks are created and no `logs/` directory exists.
2.  **Edge Cases:** `tests/test_logger_complex.py` verifies:
    -   **JSON Toggling:** Switching `COREASON_LOG_JSON` correctly routes to `stdout` with JSON serialization.
    -   **Invalid Configuration:** Invalid log levels gracefully default to `INFO`.
    -   **Reconfiguration:** Repeated calls to `configure_logging()` do not duplicate handlers.
    -   **Concurrency:** Logging during high-concurrency scenarios does not cause race conditions or crashes.
