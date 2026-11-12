from django import forms
from django.contrib.auth.models import User


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        # ruleid: DJANGO-MASS-ASSIGN
        fields = "__all__"
