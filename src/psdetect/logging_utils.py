"""Logging helpers with loguru and tqdm-friendly console output."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from tqdm.auto import tqdm

try:
    from loguru import logger as _loguru_logger

    logger = _loguru_logger
    _HAS_LOGURU = True
except ImportError:  # pragma: no cover
    logger = logging.getLogger("psdetect")
    _HAS_LOGURU = False


def _tqdm_sink(message: Any) -> None:
    text = str(message).rstrip("\n")
    if text:
        tqdm.write(text)


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    normalized = level.upper()
    if _HAS_LOGURU:
        logger.remove()
        logger.add(
            _tqdm_sink,
            level=normalized,
            colorize=True,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                "<level>{message}</level>"
            ),
            enqueue=False,
            backtrace=False,
            diagnose=False,
        )
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            logger.add(
                log_file,
                level=normalized,
                colorize=False,
                enqueue=False,
                backtrace=False,
                diagnose=False,
                rotation="25 MB",
                retention=5,
                format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
            )
        logger.debug("Logging configured with loguru at level {}", normalized)
        return

    logging.basicConfig(
        level=getattr(logging, normalized, logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
        logger.addHandler(file_handler)
    logger.debug("Logging configured with stdlib fallback at level %s", normalized)
