from django.contrib import admin
from django.urls import path
from records import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('login/', views.user_login, name='login'),
    path('signup/', views.user_signup, name='signup'),
    path('logout/', views.user_logout, name='logout'),
    
    # Authenticated views
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add-record/', views.add_patient_record, name='add_record'),
    path('decrypt-record/', views.decrypt_record, name='decrypt_record'),
    path('performance-test/', views.performance_test, name='performance_test'),
    path('patient-records/', views.patient_records_list, name='patient_records'),
    path('download-stego/<str:filename>/', views.download_stego_image, name='download_stego'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)