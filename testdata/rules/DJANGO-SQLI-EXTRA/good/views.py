import logging

from .models import Entry

logger = logging.getLogger(__name__)


def search(request, parser):
    q = request.GET.get("q", "")
    options = parser.extra("--verbose")
    logger.info("search", extra={"q": q, "options": options})
    return Entry.objects.filter(headline=q)
