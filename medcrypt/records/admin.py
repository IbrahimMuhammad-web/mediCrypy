from django.contrib import admin
from .models import PatientRecord, PerformanceTest

admin.site.register(PatientRecord)
admin.site.register(PerformanceTest)