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
router.register(r'users', UserViewSet)

urlpatterns = [
    url(r'^', include(router.urls)),
    path('admin/', admin.site.urls),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'', include('user_sessions.urls', 'user_sessions')),
    path('accounts/', include('django.contrib.auth.urls')),
    url(r"^get_token/",get_token),
    url(r"^validate_token/",validate_token),
#    url(r"^login/",login),
    url(r"^login/",challenge_login),
    url(r"^token_login/",token_login),
    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),

]


