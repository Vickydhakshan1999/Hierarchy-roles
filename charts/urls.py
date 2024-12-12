from django.urls import path
from . import views

urlpatterns = [
    path('generate-bar-chart/', views.generate_bar_chart, name='generate_bar_chart'),
]
