import logging

logger = logging.getLogger(__name__)


def describe(cfg, has_session_token):
    logger.info(
        "config: region=%s has_secret_key=%s has_session_token=%s key_set=%s",
        cfg.region,
        cfg.has_secret_key,
        has_session_token,
        bool(cfg.api_key),
    )
