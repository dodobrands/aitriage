import logging

logger = logging.getLogger(__name__)


def report(usage):
    logger.info(f"used {usage.total_tokens} tokens, max_tokens={usage.max_tokens}")
    logger.info("token count %d", usage.token_count)
