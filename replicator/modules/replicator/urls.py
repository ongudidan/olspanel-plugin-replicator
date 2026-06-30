from django.urls import path
from . import views

urlpatterns = [
    path('gui/', views.gui_view, name='replicator_gui'),
    path('test-ssh/', views.test_ssh_view, name='replicator_test_ssh'),
    path('fetch-inventory/', views.fetch_inventory_view, name='replicator_fetch_inventory'),
    path('start/', views.start_migration_view, name='replicator_start'),
    path('stream/<int:job_id>/', views.stream_logs_view, name='replicator_stream_logs'),
    path('status/<int:job_id>/', views.job_status_view, name='replicator_job_status'),
]
