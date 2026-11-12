from django.http import HttpResponse
from django.utils.safestring import mark_safe


def greeting(request):
    name = request.GET.get("name", "")
    # ruleid: DJANGO-MARK-SAFE
    return HttpResponse(mark_safe(f"<b>Hello {name}</b>"))
