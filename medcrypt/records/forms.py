from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from .models import PatientRecord

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Username'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Password'
    }))

class SignUpForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Email'
    }))
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super(SignUpForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['class'] = 'form-control'
        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].widget.attrs['class'] = 'form-control'

class PatientRecordForm(forms.ModelForm):
    cover_image = forms.ImageField(label='Cover Image', required=True)
    
    class Meta:
        model = PatientRecord
        fields = ['patient_name', 'age', 'gender', 'cover_image']
        widgets = {
            'patient_name': forms.TextInput(attrs={'class': 'form-control'}),
            'age': forms.NumberInput(attrs={'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
        }
    
    # Additional medical fields not in the model
    blood_group = forms.CharField(max_length=10, widget=forms.TextInput(attrs={'class': 'form-control'}))
    allergies = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2}))
    diagnosis = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}))
    treatment_plan = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}))
    doctors_notes = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}))

class DecryptRecordForm(forms.Form):
    stego_image = forms.ImageField(label='Stego Image', widget=forms.FileInput(attrs={'class': 'form-control'}))
    private_key = forms.CharField(label='Private Key', widget=forms.Textarea(attrs={
        'class': 'form-control',
        'rows': 5,
        'placeholder': 'Paste your private key here...'
    }))

class PerformanceTestForm(forms.Form):
    TEST_CHOICES = [
        ('RSA', 'RSA Encryption Only'),
        ('RSA_LSB', 'RSA + LSB Steganography'),
    ]
    
    test_file = forms.FileField(label='Test File', widget=forms.FileInput(attrs={'class': 'form-control'}))
    test_type = forms.ChoiceField(
        label='Test Type',
        choices=TEST_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )