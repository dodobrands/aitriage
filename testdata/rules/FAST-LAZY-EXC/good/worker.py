import logging

logger = logging.getLogger(__name__)


def refresh(cache):
    try:
        cache.refresh()
    except Exception:
        logger.exception("cache refresh failed")
    try:
        cache.close()
    except ConnectionError:
        pass  # already closed by the server
