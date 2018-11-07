from django.contrib import admin
from django.urls import path
from django.conf.urls import url, include
from django.contrib.auth.models import User
from rest_framework import routers, serializers
from login.views import *

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
router = routers.DefaultRouter()
router.register(r'profiles', ProfileViewSet)

urlpatterns = [
    url(r'^', include(router.urls)),
    path('admin/', admin.site.urls),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('accounts/', include('django.contrib.auth.urls')),
]


