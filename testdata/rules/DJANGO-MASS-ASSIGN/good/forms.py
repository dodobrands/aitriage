import strawberry_django
from django import forms
from django.contrib.auth.models import User
from django.contrib.sites.models import Site


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        # fields = "__all__" would expose is_staff and is_superuser.


# Read-only GraphQL output type: no user input is bound to it.
@strawberry_django.type(
    Site,
    fields="__all__",
)
class SiteType:
    pass
