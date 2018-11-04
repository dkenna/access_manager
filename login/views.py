from django.shortcuts import render
from login.models import Profile
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets

class ProfileSerializer(serializers.HyperlinkedModelSerializer):
    user = serializers.HyperlinkedIdentityField(view_name='profile-detail')
    class Meta:
        model = Profile
        fields = ('user', 'public_key')

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

