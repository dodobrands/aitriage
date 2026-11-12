import logging

logger = logging.getLogger(__name__)


def call_llm(provider_api_key):
    # ruleid: PY-LOGGING-SENSITIVE
    logger.debug("calling provider with %s", provider_api_key)
