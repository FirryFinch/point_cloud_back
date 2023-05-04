"""
URL configuration for point_cloud project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import path, include

from point_cloud_back import settings

urlpatterns = [
    path('', include('point_cloud_app.urls_app')),
    path('admin/', admin.site.urls),
]

handler404 = 'point_cloud_app.views.err404'
handler400 = 'point_cloud_app.views.err400'
handler403 = 'point_cloud_app.views.err403'
handler500 = 'point_cloud_app.views.err500'

