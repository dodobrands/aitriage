import logging

logger = logging.getLogger(__name__)


def signup(form):
    # ruleid: PY-LOGGING-SENSITIVE
    logger.info("new signup %s / %s", form["email"], form["password"])
