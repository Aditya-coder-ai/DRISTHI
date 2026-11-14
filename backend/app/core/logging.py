"""Structured logging configuration for DRISTHI Central Backend."""

import logging
import re
import sys
from typing import Any


class CredentialRedactingFilter(logging.Filter):
    """Prevents sensitive password or key patterns from leaking into log outputs."""

    PASSWORD_PATTERN = re.compile(r'(?i)(password|passwd|secret|api_key|token)["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?')

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.PASSWORD_PATTERN.sub(r'\1: [REDACTED]', record.msg)
        return True


def get_backend_logger(name: str = "drishti.backend") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        handler.addFilter(CredentialRedactingFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


logger = get_backend_logger()

