from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


# ruleid: DJANGO-CSRF-EXEMPT
@method_decorator(csrf_exempt, name="dispatch")
class TransferView(View):
    def post(self, request):
        return self.transfer(request)
