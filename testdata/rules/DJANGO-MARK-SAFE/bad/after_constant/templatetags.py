from django import template
from django.utils.safestring import mark_safe

register = template.Library()
PLACEHOLDER = mark_safe("&mdash;")


@register.filter
def bold(value):
    # ruleid: DJANGO-MARK-SAFE
    return mark_safe("<b>%s</b>" % value)
