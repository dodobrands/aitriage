from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect


# Do not add @csrf_exempt here: this form posts with the session cookie.
@csrf_protect
def transfer(request):
    """Withdraw money. Never wrap this view in csrf_exempt(view)."""
    amount = int(request.POST["amount"])
    request.user.account.withdraw(amount)
    return JsonResponse({"ok": True})
