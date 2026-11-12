from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse

from .models import Invoice


@user_passes_test(lambda u: u.is_active and u.is_staff)
def invoice_detail(request, pk):
    invoice = Invoice.objects.get(pk=pk, owner=request.user)
    return JsonResponse({"id": invoice.pk, "total": str(invoice.total)})
