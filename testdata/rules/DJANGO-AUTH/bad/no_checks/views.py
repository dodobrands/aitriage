from django.http import JsonResponse

from .models import Invoice


# TODO: add @login_required before launch
def invoice_detail(request, pk):
    invoice = Invoice.objects.get(pk=pk)
    return JsonResponse({"id": invoice.pk, "total": str(invoice.total)})
