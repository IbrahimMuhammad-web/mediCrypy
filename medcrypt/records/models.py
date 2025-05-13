from django.db import models
from django.contrib.auth.models import User

class PatientRecord(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    original_filename = models.CharField(max_length=255)
    stego_filename = models.CharField(max_length=255)
    public_key = models.TextField()
    private_key = models.TextField()
    
    # Metadata fields (not encrypted, for searchability)
    patient_name = models.CharField(max_length=100)
    age = models.PositiveSmallIntegerField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    
    def __str__(self):
        return f"Record for {self.patient_name} ({self.created_at})"

class PerformanceTest(models.Model):
    TEST_TYPE_CHOICES = [
        ('RSA', 'RSA Only'),
        ('RSA_LSB', 'RSA + LSB Steganography'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    test_date = models.DateTimeField(auto_now_add=True)
    test_type = models.CharField(max_length=10, choices=TEST_TYPE_CHOICES)
    file_size = models.PositiveIntegerField()  # in bytes
    encryption_time = models.FloatField()  # in seconds
    decryption_time = models.FloatField()  # in seconds
    memory_usage = models.FloatField()  # in MB
    avalanche_effect = models.FloatField()  # percentage
    entropy_before = models.FloatField()
    entropy_after = models.FloatField()
    
    def __str__(self):
        return f"{self.get_test_type_display()} Test ({self.test_date})"