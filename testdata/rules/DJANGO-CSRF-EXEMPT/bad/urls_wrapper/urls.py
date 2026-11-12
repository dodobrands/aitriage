from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    # ruleid: DJANGO-CSRF-EXEMPT
    path("transfer/", csrf_exempt(views.TransferView.as_view())),
]
