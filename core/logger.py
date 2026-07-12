import logging
import os
from datetime import datetime
from rich.logging import RichHandler
from config.settings import config


def setup_logger(name: str, log_file: str = None) -> logging.Logger:
    """Set up a logger with both console and file handlers."""

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL))

    # Rich console handler
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=False
    )
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler
    if log_file is None:
        log_file = config.LOG_DIR / f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(config.LOG_FORMAT)
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    return logger