import logging

log = logging.getLogger(__name__)


def connect(cfg):
    # ruleid: PY-LOGGING-SENSITIVE
    log.warning(
        "connecting with key %s",
        cfg.api_key,
    )
