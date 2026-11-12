from .models import Entry


def search(request):
    q = request.GET.get("q", "")
    # ruleid: DJANGO-RAW-SQL
    return Entry.objects.extra(where=["headline = '%s'" % q])
