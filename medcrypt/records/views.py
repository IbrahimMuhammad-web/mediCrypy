from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, FileResponse
from django.conf import settings
from .forms import LoginForm, SignUpForm, PatientRecordForm, DecryptRecordForm, PerformanceTestForm
from .models import PatientRecord, PerformanceTest
from .utils import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    embed_lsb, extract_lsb, measure_performance,
    text_to_binary, binary_to_text
)
import os
import uuid
import tempfile
import rsa
from datetime import datetime
import json
from django.core.files.storage import FileSystemStorage

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'records/home.html')

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
    else:
        form = LoginForm()
    return render(request, 'records/login.html', {'form': form})

def user_signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')
    else:
        form = SignUpForm()
    return render(request, 'records/signup.html', {'form': form})

@login_required
def user_logout(request):
    logout(request)
    return redirect('home')

@login_required
def dashboard(request):
    return render(request, 'records/dashboard.html')

@login_required
def add_patient_record(request):
    if request.method == 'POST':
        form = PatientRecordForm(request.POST, request.FILES)
        if form.is_valid():
            # Generate RSA keys
            pub_key, priv_key = generate_rsa_keys()
            
            # Prepare patient data
            patient_data = {
                'full_name': form.cleaned_data['patient_name'],
                'age': form.cleaned_data['age'],
                'gender': form.cleaned_data['gender'],
                'blood_group': form.cleaned_data['blood_group'],
                'allergies': form.cleaned_data['allergies'],
                'diagnosis': form.cleaned_data['diagnosis'],
                'treatment_plan': form.cleaned_data['treatment_plan'],
                'doctors_notes': form.cleaned_data['doctors_notes'],
            }
            patient_data_str = json.dumps(patient_data)
            
            # Encrypt the data
            encrypted_data = rsa_encrypt(patient_data_str, pub_key)
            
            # Save the cover image temporarily
            cover_image = form.cleaned_data['cover_image']
            fs = FileSystemStorage()
            original_filename = fs.save(cover_image.name, cover_image)
            original_path = fs.path(original_filename)
            
            # Generate unique filename for stego image
            stego_filename = f"stego_{uuid.uuid4().hex}.png"
            stego_path = os.path.join(settings.MEDIA_ROOT, stego_filename)
            
            # Embed encrypted data into image
            embed_lsb(original_path, encrypted_data.hex(), stego_path)
            
            # Save record metadata to database
            record = PatientRecord(
                user=request.user,
                original_filename=original_filename,
                stego_filename=stego_filename,
                public_key=pub_key.save_pkcs1().decode('utf-8'),
                private_key=priv_key.save_pkcs1().decode('utf-8'),
                patient_name=form.cleaned_data['patient_name'],
                age=form.cleaned_data['age'],
                gender=form.cleaned_data['gender'],
            )
            record.save()
            
            # Clean up original file
            os.remove(original_path)
            
            # Prepare context for success page
            context = {
                'record': record,
                'private_key': priv_key.save_pkcs1().decode('utf-8'),
                'stego_url': os.path.join(settings.MEDIA_URL, stego_filename),
            }
            
            return render(request, 'records/record_success.html', context)
    else:
        form = PatientRecordForm()
    
    return render(request, 'records/add_record.html', {'form': form})

@login_required
def download_stego_image(request, filename):
    file_path = os.path.join(settings.MEDIA_ROOT, filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    return HttpResponse("File not found", status=404)

@login_required
def decrypt_record(request):
    if request.method == 'POST':
        form = DecryptRecordForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                # Save uploaded stego image temporarily
                stego_image = form.cleaned_data['stego_image']
                fs = FileSystemStorage()
                stego_filename = fs.save(stego_image.name, stego_image)
                stego_path = fs.path(stego_filename)
                
                # Get private key
                private_key_str = form.cleaned_data['private_key']
                try:
                    priv_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode('utf-8'))
                except (ValueError, IndexError):
                    return render(request, 'records/decrypt_error.html', {
                        'error': 'Invalid private key format'
                    })
                
                # Extract data from stego image
                try:
                    # We don't know the exact length, so we'll extract a large amount
                    extracted_hex = extract_lsb(stego_path, 100000)  # Large enough for our encrypted data
                    encrypted_data = bytes.fromhex(extracted_hex)
                    
                    # Decrypt the data
                    decrypted_data = rsa_decrypt(encrypted_data, priv_key)
                    patient_data = json.loads(decrypted_data)
                    
                    # Clean up
                    os.remove(stego_path)
                    
                    return render(request, 'records/decrypt_success.html', {
                        'patient_data': patient_data
                    })
                except Exception as e:
                    os.remove(stego_path)
                    return render(request, 'records/decrypt_error.html', {
                        'error': f'Decryption failed: {str(e)}'
                    })
            except Exception as e:
                return render(request, 'records/decrypt_error.html', {
                    'error': f'An error occurred: {str(e)}'
                })
    else:
        form = DecryptRecordForm()
    
    return render(request, 'records/decrypt_record.html', {'form': form})

@login_required
def performance_test(request):
    if request.method == 'POST':
        form = PerformanceTestForm(request.POST, request.FILES)
        if form.is_valid():
            test_file = form.cleaned_data['test_file']
            test_type = form.cleaned_data['test_type']
            
            # Save the test file temporarily
            fs = FileSystemStorage()
            filename = fs.save(test_file.name, test_file)
            file_path = fs.path(filename)
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read().decode('utf-8', errors='ignore')
            
            # Prepare image path if needed
            image_path = None
            if test_type == 'RSA_LSB':
                # Use a sample image for LSB embedding (in a real app, you might let users upload one)
                image_path = os.path.join(settings.STATIC_ROOT, 'images', 'sample_cover.png')
                if not os.path.exists(image_path):
                    # Create a simple image if sample doesn't exist
                    from PIL import Image
                    img = Image.new('RGB', (100, 100), color='white')
                    image_path = os.path.join(settings.MEDIA_ROOT, 'temp_cover.png')
                    img.save(image_path)
            
            # Measure performance
            results = measure_performance(test_type, file_content, image_path)
            
            # Save test results to database
            test = PerformanceTest(
                user=request.user,
                test_type=test_type,
                file_size=len(file_content.encode('utf-8')),
                encryption_time=results['encryption_time'],
                decryption_time=results['decryption_time'],
                memory_usage=results['encryption_memory'],
                avalanche_effect=results['avalanche_effect'],
                entropy_before=results['entropy_before'],
                entropy_after=results['entropy_after'],
            )
            test.save()
            
            # Clean up
            os.remove(file_path)
            if image_path and 'temp_cover.png' in image_path:
                os.remove(image_path)
            
            # Get all tests for charts
            tests = PerformanceTest.objects.filter(user=request.user).order_by('test_date')
            
            return render(request, 'records/performance_results.html', {
                'results': results,
                'tests': tests,
                'test_type': test_type,
            })
    else:
        form = PerformanceTestForm()
    
    return render(request, 'records/performance_test.html', {'form': form})

@login_required
def patient_records_list(request):
    records = PatientRecord.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'records/patient_records.html', {'records': records})