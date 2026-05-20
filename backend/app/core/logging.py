"""Logging configuration for the backend service."""

import logging


def configure_logging() -> None:
    """Configure standard application logging for local and Docker runs."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
