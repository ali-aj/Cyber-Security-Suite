from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('xss_scan/', views.xss_scan, name='xss_scan'),
    path('rsa/', views.rsa, name='rsa'),
    path('aes/', views.aes, name='aes'),
    path('des/', views.des, name='des'),
    path('hill_cipher/', views.hill_cipher, name='hill_cipher'),
    path('validate_primitive_root/', views.validate_primitive_root, name='validate_primitive_root'),
    path('elgamal/', views.elgamal, name='elgamal'),
    path('diffie_hellman/', views.diffie_hellman, name='diffie_hellman'),
    path('crypto/', views.crypto, name='crypto'),
    path('ids/', views.intrusion_detection, name='intrusion_detection'),
    path('buffer_overflow/', views.buffer_overflow_sim, name='buffer_overflow'),
    path('brute_force/', views.brute_force_sim, name='brute_force'),
    path('scan_history/', views.scan_history, name='scan_history'),
    path('ids_logs/', views.ids_logs, name='ids_logs'),
    path('crypto_history/', views.crypto_history, name='crypto_history'),
] 
