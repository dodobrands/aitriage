from .models import Entry


def search(request):
    q = request.GET.get("q", "")
    # ruleid: DJANGO-SQLI-EXTRA
    return Entry.objects.extra(where=["headline = %s"], params=[q])
