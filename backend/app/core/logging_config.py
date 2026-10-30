import logging
import os
import re
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings

# Sensitive query params to mask if present
SENSITIVE_PARAM_PATTERN = re.compile(
    r"(?i)(token|key|password|secret|auth|api_key|access_token|session)=([^&]+)"
)


def sanitize_url_for_logging(url: str) -> str:
    """
    Sanitizes URL for safe logging by removing or masking sensitive query parameters.
    """
    if not url:
        return ""
    try:
        parsed = urlsplit(url)
        if not parsed.query:
            return url
        # Mask sensitive query params
        sanitized_query = SENSITIVE_PARAM_PATTERN.sub(r"\1=***", parsed.query)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, sanitized_query, ""))
    except Exception:
        return "<malformed_url>"


def setup_logging() -> logging.Logger:
    """
    Sets up centralized logging for console and file output.
    """
    log_dir = os.path.dirname(settings.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    log_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(log_formatter)
        root_logger.addHandler(console_handler)

    if not any(isinstance(h, logging.FileHandler) for h in root_logger.handlers):
        try:
            file_handler = logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(log_formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.warning(f"Could not initialize file handler at {settings.LOG_FILE}: {e}")

    logger = logging.getLogger("aegis")
    logger.info("AEGIS logging initialized successfully.")
    return logger


logger = logging.getLogger("aegis")
