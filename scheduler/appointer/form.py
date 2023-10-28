from django import forms
from .models import User

class SignupForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email','password' ,'first_name', 'last_name', 'account_type', 'specialization','salt']


class loginform(forms.ModelForm):
    class Meta:
        model=User
        fields=["email",'password']