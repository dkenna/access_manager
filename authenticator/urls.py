from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url, include
from django.contrib.auth.models import User
from rest_framework import routers, serializers
from login.views import *
from django.conf.urls.static import static
from django.conf import settings

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
    #path('accounts/', include('django.contrib.auth.urls')),
    url(r"^get_jwks/?",get_jwks),
    #url(r"^get_pem/?",get_pem),
    #url(r"^get_auth_challenge/?",get_auth_challenge),
    #url(r"^get_update_challenge/?",get_update_challenge),
    #url(r"^update_pub_key/?",update_pub_key),
    #url(r"^get_update_token/?",get_update_token),
    #url(r"^clogin/?",challenge_login), #with form
    url(r"^plogin_/?",passphrase_login_json),
    #url(r"^plogin/?",passphrase_login), #<--- old form login
    #url(r"^token_login/?",token_login),
    url(r"^validate_token/?",validate_token),
    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),
    re_path('^', get_404),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) 


