from django.http import HttpResponse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

PLACEHOLDER = mark_safe("&mdash;")


def greeting(request):
    # format_html() escapes its arguments, unlike mark_safe(value).
    return HttpResponse(format_html("<b>Hello {}</b>", request.GET.get("name", "")))
