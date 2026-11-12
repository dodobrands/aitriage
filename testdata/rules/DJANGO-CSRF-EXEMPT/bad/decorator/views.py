from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


# ruleid: DJANGO-CSRF-EXEMPT
@csrf_exempt
def transfer(request):
    amount = int(request.POST["amount"])
    request.user.account.withdraw(amount)
    return JsonResponse({"ok": True})
