import logging
import re
import sys
from typing import Any

import structlog

from app.core.config import get_settings


_CPF_RE = re.compile(r"\b(\d{3})\d{5}(\d{3})\b")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]+")
_LONG_DIGITS_RE = re.compile(r"\b\d{13,19}\b")


def _mask_string(value: str) -> str:
    if not value:
        return value
    value = _CPF_RE.sub(r"\1.***.***-\2", value)
    value = _EMAIL_RE.sub(r"\1***\2", value)
    value = _BEARER_RE.sub(r"\1***REDACTED***", value)
    value = _LONG_DIGITS_RE.sub(lambda m: "****" + m.group()[-4:], value)
    return value


def _walk_and_mask(obj: Any) -> Any:
    if isinstance(obj, str):
        return _mask_string(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_mask(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(_walk_and_mask(v) for v in obj)
    return obj


def pii_masking_processor(_, __, event_dict: dict) -> dict:
    """Última linha de defesa: mascara PII em qualquer campo do log."""
    return _walk_and_mask(event_dict)


def configure_logging() -> None:
    settings = get_settings()
    level = logging.INFO if settings.is_prod else logging.DEBUG

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        pii_masking_processor,
    ]

    structlog.configure(
        processors=shared_processors + [structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
