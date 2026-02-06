# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import logging
import os
import sys
from pathlib import Path
from typing import Any

from loguru import logger
from opentelemetry import trace

__all__ = ["logger", "configure_logging"]


class InterceptHandler(logging.Handler):
    """
    Redirects standard logging messages to Loguru.
    Ensures libraries using standard logging are captured uniformly.
    """

    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno  # type: ignore[assignment]

        # Find caller from where originated the logged message
        frame = logging.currentframe()
        depth = 2
        while frame and (
            frame.f_code.co_filename == logging.__file__
            or frame.f_code.co_filename == __file__
        ):
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def trace_id_injector(record: dict[str, Any]) -> None:
    """
    Injects OpenTelemetry trace_id and span_id into the log record.
    Used as a patcher for Loguru.
    """
    span = trace.get_current_span()
    # Check if we have an active span that is valid
    ctx = span.get_span_context()
    if ctx.is_valid:
        # Inject into 'extra' so it appears in JSON output and can be used in format
        record["extra"]["trace_id"] = format(ctx.trace_id, "032x")
        record["extra"]["span_id"] = format(ctx.span_id, "016x")
        # Inject correlation_id for easier searching
        record["extra"]["correlation_id"] = format(ctx.trace_id, "032x")


def configure_logging() -> None:
    """
    Configures the logger based on environment variables.
    Call this to reload configuration if env vars change.
    """
    log_level = os.getenv("COREASON_LOG_LEVEL", "INFO").upper()
    log_json = os.getenv("COREASON_LOG_JSON", "false").lower() == "true"

    # Verify level exists in Loguru, default to INFO if not
    try:
        logger.level(log_level)
    except ValueError:
        log_level = "INFO"

    # Remove default handler and any previously added handlers
    # logger.configure(handlers=[]) ensures no default handler is added back
    # and sets the patcher in one go.
    logger.configure(handlers=[], patcher=trace_id_injector)

    # Ensure logs directory exists and add file sink
    try:
        log_path = Path("logs")
        if not log_path.exists():
            log_path.mkdir(parents=True, exist_ok=True)  # pragma: no cover
    except (PermissionError, OSError):
        # In read-only environments (e.g. some containers), we might fail to create dir.
        # We'll skip file logging in that case.
        pass

    # Sink 1: Console (Stdout/Stderr)
    if log_json:
        # JSON logs to stdout are preferred for containerized environments
        logger.add(
            sys.stdout,
            level=log_level,
            serialize=True,
        )
    else:
        # Human-readable logs to stderr
        # We can optionally include trace_id in the text format if present
        format_str = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )

        # If we wanted to include trace_id in text:
        # format_str += " | {extra[trace_id]}"
        # But we need to handle if it's missing. Loguru handles missing keys in extra gracefully?
        # No, it raises KeyError usually unless we use {extra.get(...)}.
        # For now, keep it simple. Enterprise usage usually assumes JSON for tracing.

        logger.add(
            sys.stderr,
            level=log_level,
            format=format_str,
        )

    # Sink 2: File (JSON, Rotation, Retention)
    # Always JSON for file to allow structured analysis later
    try:
        logger.add(
            "logs/app.log",
            rotation="500 MB",
            retention="10 days",
            serialize=True,
            enqueue=True,
            level=log_level,
        )
    except (PermissionError, OSError):
        # Fail silently if we can't write to file (e.g. read-only filesystem)
        pass

    # Intercept standard logging
    # Force=True ensures we override existing config
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)

    # Set the root logger level to match our configured level to avoid processing excessive debug logs
    numeric_level = logging.getLevelName(log_level)
    if isinstance(numeric_level, int):
        logging.getLogger().setLevel(numeric_level)
    else:
        # Fallback if invalid level string
        logging.getLogger().setLevel(logging.INFO)


# Initialize on import
configure_logging()
