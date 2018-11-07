from django.shortcuts import render
from login.models import Profile
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets

class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.HyperlinkedRelatedField(
        many=False,
        read_only=True,
        view_name='user-detail'
    )
    class Meta:
        model = Profile
        fields = ('user', 'public_key')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

